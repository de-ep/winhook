#ifndef DEF
#define DEF 

#include <windows.h>
#include <iostream>
#include <stddef.h>


typedef NTSTATUS (NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE ,
    PVOID* ,
    ULONG_PTR ,
    PSIZE_T ,
    ULONG ,
    ULONG 
);

LPVOID va_NtAllocateVirtualMemory;
NtAllocateVirtualMemory_t tramp_NtAllocateVirtualMemory = nullptr;

NTSTATUS dummy_NtAllocateVirtualMemory_t(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection   
) {
    printf("inside hooked fn\n");

    return tramp_NtAllocateVirtualMemory(
        ProcessHandle,
        BaseAddress,
        ZeroBits,
        RegionSize,
        AllocationType,
        PageProtection
    );
}


#endif
