#include "hooks.h"


void install_hook(LPCSTR orig_func, LPCSTR from_module, LPVOID hooked_func_add, LPVOID* va) {

    //getting address of target function
    LPVOID orig_func_add = (LPVOID)GetProcAddress(GetModuleHandleA(from_module), orig_func);
    if (!orig_func_add) {
        printf("[ERROR] %d\n", GetLastError());
        exit(EXIT_FAILURE);
    }


    //preparing patch
    unsigned char patch[] = {
        0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                        //mov r8, address_of_hooked_function
        0x41, 0xFF, 0xE0,                                                                  //jmp r8
        0x90, 0x90, 0x90
    };

    memcpy(&patch[2], &hooked_func_add, sizeof(LPVOID));


    //reading original bytes before patching
    unsigned char orig_bytes[sizeof(patch)] = { 0 };
    size_t bytes_read = 0;

    BOOL rpm = ReadProcessMemory(GetCurrentProcess(), orig_func_add, orig_bytes, sizeof(orig_bytes), &bytes_read);
    if (bytes_read < sizeof(patch) || !rpm) {
        printf("[ERROR] %d\n", GetLastError());
        exit(EXIT_FAILURE);
    }


    //changing protections so we can patch
    DWORD vp_old_protection;
    BOOL vp = VirtualProtect(orig_func_add, sizeof(patch), PAGE_EXECUTE_READWRITE, &vp_old_protection);
    if (!vp) {
        printf("[ERROR] %d\n", GetLastError());
        exit(EXIT_FAILURE);
    }


    //allocating our tramp before we hook in case we hook NtAllocateVirtualMemory
    unsigned char patch2[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,                                              //end of orignal bytes
        0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    //mov r8 , address_of_origial_func + size_of_patch
        0x41, 0xFF, 0xE0,                                              //jmp r8
        0x90, 0x90, 0x90
    };

    *va = VirtualAlloc(NULL, sizeof(patch2), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!*va) {
        printf("[ERROR] %d\n", GetLastError());
        exit(EXIT_FAILURE);
    }


    //patching
    BOOL wpm = WriteProcessMemory(GetCurrentProcess(), orig_func_add, &patch, sizeof(patch), &bytes_read);
    if (bytes_read < sizeof(patch) || !wpm) {
        printf("[ERROR] %d\n", GetLastError());
        exit(EXIT_FAILURE);
    }


    //preparing trampoline
    memcpy(&patch2, &orig_bytes, sizeof(orig_bytes));


    LPVOID orig_func_add_after_patch = (LPVOID)((long long unsigned int)orig_func_add + sizeof(patch));
    memcpy(&patch2[sizeof(patch) + 2], &orig_func_add_after_patch, sizeof(LPVOID));

    memcpy(*va, &patch2, sizeof(patch2));

    return;
}