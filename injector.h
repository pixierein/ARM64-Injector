#ifndef INJECTOR_H
#define INJECTOR_H

#include <mach/mach.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#define DYLIB_PATH_MAX 1024
#define SHELLCODE_MAX  256

typedef struct {
    pid_t   TargetPid;
    char    DylibPath[DYLIB_PATH_MAX];
    task_t  TaskPort;
} InjectionContext;

bool InitializeContext(InjectionContext *Context, const char *ProcessName, const char *DylibPath);
bool AttachToProcess(InjectionContext *Context);
bool PerformInjection(InjectionContext *Context);
void CleanupContext(InjectionContext *Context);

pid_t FindProcessByName(const char *ProcessName);

#endif
