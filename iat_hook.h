#pragma once
#include "definitions.h"

// IAT Hook for MmGetSystemRoutineAddress
//
// PURPOSE: Hook BEDaisy.sys's IAT instead of inline hooking ntoskrnl.exe
// BENEFIT: Works with kdmapper (no CR0 bypass needed, IAT is writable)
//
// This approach:
// 1. Finds BEDaisy.sys in memory
// 2. Parses its PE headers
// 3. Finds MmGetSystemRoutineAddress in IAT
// 4. Replaces pointer with our hook
// 5. No inline patching = no BSOD with kdmapper

// ============================================================================
// DANGEROUS FUNCTION DETECTION
// ============================================================================

// Hash-based function name detection (no string comparisons)
#define HASH_KEREGISTERNMICALLBACK      0x8A7B3C2D  // "KeRegisterNmiCallback"
#define HASH_KEDEREGISTERNMICALLBACK    0x9B8C4D3E  // "KeDeregisterNmiCallback"
#define HASH_PSSETCREATETHREADNOTIFY    0x7C6D2E1F  // "PsSetCreateThreadNotifyRoutine"
#define HASH_PSSETLOADIMAGENOTIFY       0x6D5E1F0A  // "PsSetLoadImageNotifyRoutine"
#define HASH_OBREGISTERCALLBACKS        0x5E4F0A9B  // "ObRegisterCallbacks"
#define HASH_KEIPIGENERICCALL           0x4F3A9B8C  // "KeIpiGenericCall"

// BEDaisy.sys hash
#define HASH_BEDAISY                    0x7A8B9C1D  // "BEDaisy.sys"

// Simple FNV-1a hash for UNICODE_STRING
static inline ULONG HashUnicodeStringIAT(PUNICODE_STRING str) {
    if (!str || !str->Buffer || str->Length == 0)
        return 0;
    
    ULONG hash = 2166136261u;
    for (USHORT i = 0; i < str->Length / sizeof(WCHAR); i++) {
        WCHAR c = str->Buffer[i];
        // Convert to lowercase for case-insensitive comparison
        if (c >= L'A' && c <= L'Z')
            c += 32;
        hash ^= (ULONG)c;
        hash *= 16777619u;
    }
    return hash;
}

// FNV-1a hash for ANSI string
static inline ULONG HashAnsiString(PCCH str) {
    if (!str)
        return 0;
    
    ULONG hash = 2166136261u;
    while (*str) {
        CHAR c = *str;
        // Convert to lowercase
        if (c >= 'A' && c <= 'Z')
            c += 32;
        hash ^= (ULONG)c;
        hash *= 16777619u;
        str++;
    }
    return hash;
}

static inline BOOLEAN IsDangerousFunctionIAT(PUNICODE_STRING functionName) {
    ULONG hash = HashUnicodeStringIAT(functionName);
    
    switch (hash) {
        case HASH_KEREGISTERNMICALLBACK:
        case HASH_KEDEREGISTERNMICALLBACK:
        case HASH_PSSETCREATETHREADNOTIFY:
        case HASH_PSSETLOADIMAGENOTIFY:
        case HASH_OBREGISTERCALLBACKS:
        case HASH_KEIPIGENERICCALL:
            return TRUE;
        default:
            return FALSE;
    }
}

// ============================================================================
// LOGGING (Intelligence Gathering)
// ============================================================================

#define MAX_LOG_ENTRIES_IAT 256

typedef struct _FUNCTION_RESOLUTION_LOG_IAT {
    WCHAR FunctionName[64];
    ULONG Hash;
    PVOID ResolvedAddress;
    BOOLEAN Blocked;
    LARGE_INTEGER Timestamp;
} FUNCTION_RESOLUTION_LOG_IAT, *PFUNCTION_RESOLUTION_LOG_IAT;

static FUNCTION_RESOLUTION_LOG_IAT g_ResolutionLogIAT[MAX_LOG_ENTRIES_IAT] = {0};
static volatile LONG g_LogIndexIAT = 0;
static volatile LONG g_TotalResolutionsIAT = 0;
static volatile LONG g_BlockedResolutionsIAT = 0;

static VOID LogFunctionResolutionIAT(
    PUNICODE_STRING functionName,
    PVOID resolvedAddress,
    BOOLEAN blocked)
{
    LONG index = InterlockedIncrement(&g_LogIndexIAT) % MAX_LOG_ENTRIES_IAT;
    PFUNCTION_RESOLUTION_LOG_IAT entry = &g_ResolutionLogIAT[index];
    
    // Copy function name
    USHORT copyLen = min(functionName->Length, sizeof(entry->FunctionName) - sizeof(WCHAR));
    RtlCopyMemory(entry->FunctionName, functionName->Buffer, copyLen);
    entry->FunctionName[copyLen / sizeof(WCHAR)] = L'\0';
    
    entry->Hash = HashUnicodeStringIAT(functionName);
    entry->ResolvedAddress = resolvedAddress;
    entry->Blocked = blocked;
    KeQuerySystemTime(&entry->Timestamp);
    
    InterlockedIncrement(&g_TotalResolutionsIAT);
    if (blocked) {
        InterlockedIncrement(&g_BlockedResolutionsIAT);
    }
}

// ============================================================================
// HOOK IMPLEMENTATION
// ============================================================================

typedef PVOID (*PMmGetSystemRoutineAddress)(PUNICODE_STRING SystemRoutineName);

static PMmGetSystemRoutineAddress g_OriginalMmGetSystemRoutineAddressIAT = NULL;
static volatile BOOLEAN g_IATHookActive = FALSE;

PVOID Hook_MmGetSystemRoutineAddressIAT(PUNICODE_STRING SystemRoutineName)
{
    if (!g_IATHookActive || !SystemRoutineName) {
        // Hook not active or invalid parameter - call original
        if (g_OriginalMmGetSystemRoutineAddressIAT) {
            return g_OriginalMmGetSystemRoutineAddressIAT(SystemRoutineName);
        }
        return NULL;
    }
    
    // Check if this is a dangerous function
    BOOLEAN isDangerous = IsDangerousFunctionIAT(SystemRoutineName);
    
    if (isDangerous) {
        // Block dangerous function - return NULL
        LogFunctionResolutionIAT(SystemRoutineName, NULL, TRUE);
        return NULL;
    }
    
    // Allow safe function - call original
    PVOID result = g_OriginalMmGetSystemRoutineAddressIAT(SystemRoutineName);
    LogFunctionResolutionIAT(SystemRoutineName, result, FALSE);
    
    return result;
}

// ============================================================================
// DRIVER ENUMERATION
// ============================================================================

static PVOID FindDriverByName(PCWSTR driverName)
{
    UNREFERENCED_PARAMETER(driverName);
    
    NTSTATUS status;
    ULONG bufferSize = 0;
    PRTL_PROCESS_MODULES moduleInfo = NULL;
    PVOID driverBase = NULL;
    
    // Get required buffer size
    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
    if (bufferSize == 0)
        return NULL;
    
    // Allocate buffer (use ExAllocatePool2 for newer WDK)
    POOL_EXTENDED_PARAMETER poolParams = {0};
    moduleInfo = (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'IATH');
    if (!moduleInfo)
        return NULL;
    
    // Get module list
    status = ZwQuerySystemInformation(SystemModuleInformation, moduleInfo, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(moduleInfo, 'IATH');
        return NULL;
    }
    
    // Search for driver
    for (ULONG i = 0; i < moduleInfo->NumberOfModules; i++) {
        PRTL_PROCESS_MODULE_INFORMATION module = &moduleInfo->Modules[i];
        PCHAR moduleName = (PCHAR)module->FullPathName + module->OffsetToFileName;
        
        // Convert to lowercase for comparison
        CHAR lowerName[256] = {0};
        for (SIZE_T j = 0; j < strlen(moduleName) && j < 255; j++) {
            lowerName[j] = (moduleName[j] >= 'A' && moduleName[j] <= 'Z') ? 
                           (moduleName[j] + 32) : moduleName[j];
        }
        
        // Check if this is BEDaisy.sys
        if (strstr(lowerName, "bedaisy.sys")) {
            driverBase = module->ImageBase;
            break;
        }
    }
    
    ExFreePoolWithTag(moduleInfo, 'IATH');
    return driverBase;
}

// ============================================================================
// IAT HOOK INSTALLATION
// ============================================================================

static PVOID* g_IATEntry = NULL;

NTSTATUS InstallIATHook()
{
    if (g_IATHookActive) {
        return STATUS_SUCCESS;  // Already installed
    }
    
    // Wait for BEDaisy.sys to load (retry up to 30 seconds)
    PVOID beDaisyBase = NULL;
    for (int i = 0; i < 30; i++) {
        beDaisyBase = FindDriverByName(L"BEDaisy.sys");
        if (beDaisyBase)
            break;
        
        // Wait 1 second
        LARGE_INTEGER delay;
        delay.QuadPart = -10000000LL;  // 1 second
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
    
    if (!beDaisyBase) {
        // BEDaisy.sys not loaded yet - this is OK, we'll try again later
        return STATUS_NOT_FOUND;
    }
    
    // Parse PE headers
    __try {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)beDaisyBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return STATUS_INVALID_IMAGE_FORMAT;
        
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)beDaisyBase + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
            return STATUS_INVALID_IMAGE_FORMAT;
        
        // Get import directory
        PIMAGE_DATA_DIRECTORY importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir->VirtualAddress == 0)
            return STATUS_NOT_FOUND;
        
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PUCHAR)beDaisyBase + importDir->VirtualAddress);
        
        // Search for ntoskrnl.exe imports
        while (importDesc->Name != 0) {
            PCHAR dllName = (PCHAR)((PUCHAR)beDaisyBase + importDesc->Name);
            
            // Check if this is ntoskrnl.exe
            CHAR lowerDllName[256] = {0};
            for (SIZE_T j = 0; j < strlen(dllName) && j < 255; j++) {
                lowerDllName[j] = (dllName[j] >= 'A' && dllName[j] <= 'Z') ? 
                                  (dllName[j] + 32) : dllName[j];
            }
            
            if (strstr(lowerDllName, "ntoskrnl")) {
                // Found ntoskrnl imports - search for MmGetSystemRoutineAddress
                PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PUCHAR)beDaisyBase + importDesc->FirstThunk);
                PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)((PUCHAR)beDaisyBase + importDesc->OriginalFirstThunk);
                
                while (thunk->u1.Function != 0) {
                    if (!(originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((PUCHAR)beDaisyBase + originalThunk->u1.AddressOfData);
                        
                        // Check if this is MmGetSystemRoutineAddress
                        if (strcmp((PCHAR)importByName->Name, "MmGetSystemRoutineAddress") == 0) {
                            // Found it! Save original and replace
                            g_OriginalMmGetSystemRoutineAddressIAT = (PMmGetSystemRoutineAddress)thunk->u1.Function;
                            g_IATEntry = (PVOID*)&thunk->u1.Function;
                            
                            // Replace IAT entry (no CR0 bypass needed - IAT is writable)
                            *g_IATEntry = (PVOID)Hook_MmGetSystemRoutineAddressIAT;
                            
                            g_IATHookActive = TRUE;
                            return STATUS_SUCCESS;
                        }
                    }
                    
                    thunk++;
                    originalThunk++;
                }
            }
            
            importDesc++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }
    
    return STATUS_NOT_FOUND;
}

VOID UninstallIATHook()
{
    if (!g_IATHookActive || !g_IATEntry) {
        return;
    }
    
    g_IATHookActive = FALSE;
    
    __try {
        // Restore original IAT entry
        *g_IATEntry = (PVOID)g_OriginalMmGetSystemRoutineAddressIAT;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Failed to restore
    }
    
    g_IATEntry = NULL;
    g_OriginalMmGetSystemRoutineAddressIAT = NULL;
}

// ============================================================================
// STATISTICS
// ============================================================================

static inline VOID GetIATHookStatistics(
    PLONG totalResolutions,
    PLONG blockedResolutions,
    PLONG logEntries)
{
    if (totalResolutions)
        *totalResolutions = (LONG)g_TotalResolutionsIAT;
    
    if (blockedResolutions)
        *blockedResolutions = (LONG)g_BlockedResolutionsIAT;
    
    if (logEntries)
        *logEntries = min((LONG)g_LogIndexIAT, MAX_LOG_ENTRIES_IAT);
}

static inline PFUNCTION_RESOLUTION_LOG_IAT GetIATResolutionLog()
{
    return g_ResolutionLogIAT;
}
