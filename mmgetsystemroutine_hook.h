#pragma once
#include "definitions.h"

// MmGetSystemRoutineAddress Hook
//
// PURPOSE: Intercept BE's dynamic function resolution
// BENEFIT: See what functions BE is trying to use and block dangerous ones
//
// This is CRITICAL because BE only imports 6 functions and resolves
// everything else dynamically. By hooking this, we can:
// 1. Log what BE is doing (intelligence gathering)
// 2. Block NMI registration
// 3. Block callback registration
// 4. Redirect to our own implementations

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
#define HASH_ZWQUERYSYSTEMINFORMATION   0x3E2B8C7D  // "ZwQuerySystemInformation"

// Simple FNV-1a hash for UNICODE_STRING
static inline ULONG HashUnicodeString(PUNICODE_STRING str) {
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

static inline BOOLEAN IsDangerousFunction(PUNICODE_STRING functionName) {
    ULONG hash = HashUnicodeString(functionName);
    
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

#define MAX_LOG_ENTRIES 256

typedef struct _FUNCTION_RESOLUTION_LOG {
    WCHAR FunctionName[64];
    ULONG Hash;
    PVOID ResolvedAddress;
    BOOLEAN Blocked;
    LARGE_INTEGER Timestamp;
} FUNCTION_RESOLUTION_LOG, *PFUNCTION_RESOLUTION_LOG;

static FUNCTION_RESOLUTION_LOG g_ResolutionLog[MAX_LOG_ENTRIES] = {0};
static volatile LONG g_LogIndex = 0;
static volatile LONG g_TotalResolutions = 0;
static volatile LONG g_BlockedResolutions = 0;

static VOID LogFunctionResolution(
    PUNICODE_STRING functionName,
    PVOID resolvedAddress,
    BOOLEAN blocked)
{
    LONG index = InterlockedIncrement(&g_LogIndex) % MAX_LOG_ENTRIES;
    PFUNCTION_RESOLUTION_LOG entry = &g_ResolutionLog[index];
    
    // Copy function name
    USHORT copyLen = min(functionName->Length, sizeof(entry->FunctionName) - sizeof(WCHAR));
    RtlCopyMemory(entry->FunctionName, functionName->Buffer, copyLen);
    entry->FunctionName[copyLen / sizeof(WCHAR)] = L'\0';
    
    entry->Hash = HashUnicodeString(functionName);
    entry->ResolvedAddress = resolvedAddress;
    entry->Blocked = blocked;
    KeQuerySystemTime(&entry->Timestamp);
    
    InterlockedIncrement(&g_TotalResolutions);
    if (blocked) {
        InterlockedIncrement(&g_BlockedResolutions);
    }
}

// ============================================================================
// HOOK IMPLEMENTATION
// ============================================================================

typedef PVOID (*PMmGetSystemRoutineAddress)(PUNICODE_STRING SystemRoutineName);

static PMmGetSystemRoutineAddress g_OriginalMmGetSystemRoutineAddress = NULL;
static volatile BOOLEAN g_HookActive = FALSE;

PVOID Hook_MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName)
{
    if (!g_HookActive || !SystemRoutineName) {
        // Hook not active or invalid parameter - call original
        if (g_OriginalMmGetSystemRoutineAddress) {
            return g_OriginalMmGetSystemRoutineAddress(SystemRoutineName);
        }
        return NULL;
    }
    
    // Check if this is a dangerous function
    BOOLEAN isDangerous = IsDangerousFunction(SystemRoutineName);
    
    if (isDangerous) {
        // Block dangerous function - return NULL
        LogFunctionResolution(SystemRoutineName, NULL, TRUE);
        return NULL;
    }
    
    // Allow safe function - call original
    PVOID result = g_OriginalMmGetSystemRoutineAddress(SystemRoutineName);
    LogFunctionResolution(SystemRoutineName, result, FALSE);
    
    return result;
}

// ============================================================================
// HOOK INSTALLATION
// ============================================================================

// Inline hook implementation (x64)
#pragma pack(push, 1)
typedef struct _JMP_HOOK {
    UCHAR MovRax[2];      // 48 B8 = mov rax, imm64
    ULONG64 Address;      // Target address
    UCHAR JmpRax[2];      // FF E0 = jmp rax
} JMP_HOOK, *PJMP_HOOK;
#pragma pack(pop)

static UCHAR g_OriginalBytes[sizeof(JMP_HOOK)] = {0};
static BOOLEAN g_HookInstalled = FALSE;

NTSTATUS InstallMmGetSystemRoutineAddressHook()
{
    if (g_HookActive) {
        return STATUS_SUCCESS;  // Already installed
    }
    
    // Get address of MmGetSystemRoutineAddress
    UNICODE_STRING functionName = RTL_CONSTANT_STRING(L"MmGetSystemRoutineAddress");
    g_OriginalMmGetSystemRoutineAddress = (PMmGetSystemRoutineAddress)
        MmGetSystemRoutineAddress(&functionName);
    
    if (!g_OriginalMmGetSystemRoutineAddress) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    
    // Save original bytes
    __try {
        RtlCopyMemory(g_OriginalBytes, g_OriginalMmGetSystemRoutineAddress, sizeof(JMP_HOOK));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }
    
    // Build hook
    JMP_HOOK hook = {0};
    hook.MovRax[0] = 0x48;  // REX.W
    hook.MovRax[1] = 0xB8;  // MOV RAX, imm64
    hook.Address = (ULONG64)Hook_MmGetSystemRoutineAddress;
    hook.JmpRax[0] = 0xFF;  // JMP
    hook.JmpRax[1] = 0xE0;  // RAX
    
    // Disable write protection
    KIRQL oldIrql;
    CR0_REG cr0;
    
    oldIrql = KeRaiseIrqlToDpcLevel();
    cr0.Value = __readcr0();
    cr0.WriteProtect = 0;
    __writecr0(cr0.Value);
    
    // Install hook
    __try {
        RtlCopyMemory(g_OriginalMmGetSystemRoutineAddress, &hook, sizeof(JMP_HOOK));
        g_HookInstalled = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Restore write protection
        cr0.WriteProtect = 1;
        __writecr0(cr0.Value);
        KeLowerIrql(oldIrql);
        return STATUS_ACCESS_VIOLATION;
    }
    
    // Restore write protection
    cr0.WriteProtect = 1;
    __writecr0(cr0.Value);
    KeLowerIrql(oldIrql);
    
    g_HookActive = TRUE;
    
    return STATUS_SUCCESS;
}

VOID UninstallMmGetSystemRoutineAddressHook()
{
    if (!g_HookActive || !g_HookInstalled) {
        return;
    }
    
    g_HookActive = FALSE;
    
    if (!g_OriginalMmGetSystemRoutineAddress) {
        return;
    }
    
    // Disable write protection
    KIRQL oldIrql;
    CR0_REG cr0;
    
    oldIrql = KeRaiseIrqlToDpcLevel();
    cr0.Value = __readcr0();
    cr0.WriteProtect = 0;
    __writecr0(cr0.Value);
    
    // Restore original bytes
    __try {
        RtlCopyMemory(g_OriginalMmGetSystemRoutineAddress, g_OriginalBytes, sizeof(JMP_HOOK));
        g_HookInstalled = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Failed to restore - leave hook active flag as FALSE
    }
    
    // Restore write protection
    cr0.WriteProtect = 1;
    __writecr0(cr0.Value);
    KeLowerIrql(oldIrql);
    
    g_OriginalMmGetSystemRoutineAddress = NULL;
}

// ============================================================================
// STATISTICS
// ============================================================================

static inline VOID GetHookStatistics(
    PLONG totalResolutions,
    PLONG blockedResolutions,
    PLONG logEntries)
{
    if (totalResolutions)
        *totalResolutions = (LONG)g_TotalResolutions;
    
    if (blockedResolutions)
        *blockedResolutions = (LONG)g_BlockedResolutions;
    
    if (logEntries)
        *logEntries = min((LONG)g_LogIndex, MAX_LOG_ENTRIES);
}

static inline PFUNCTION_RESOLUTION_LOG GetResolutionLog()
{
    return g_ResolutionLog;
}

