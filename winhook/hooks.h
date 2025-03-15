#ifndef HOOKS
#define HOOKS

#include <windows.h>
#include <stdio.h>
#include <string.h>


#ifdef __cplusplus
extern "C" {
#endif

void install_hook(LPCSTR orig_func, LPCSTR from_module, LPVOID hooked_func_add, LPVOID* va);

#ifdef __cplusplus
}
#endif

#endif 
