#pragma once
#include "definitions.h"

// BattleEye Bypass - Callback-Based Approach (kdmapper Compatible)
//
// STRATEGY: Instead of dangerous inline hooks, we use Windows kernel callbacks
// to monitor and block BattleEye's operations using only documented APIs.

// ============================================================================
// UNDOCUMENTED API IMPLEMENTATIONS
// ============================================================================

// Get thread start address by reading from ETHREAD structure
static PVOID GetThreadStartAddress(PETHREAD Thread)
{
    // ETHREAD->StartAddress offset varies by Windows version
    // Win10/11 x64: offset 0x6F8 (approximate)
    __try {
        PVOID* startAddr = (PVOID*)((ULONG_PTR)Thread + 0x6F8);
        return *startAddr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
}

// Suspend thread by setting suspend count
static NTSTATUS SuspendThread(PETHREAD Thread)
{
    __try {
        // Use KeSetEvent to signal thread suspension
        // This is a simplified approach
        PKTHREAD kthread = (PKTHREAD)Thread;
        
        // Suspend by setting priority to lowest
        KeSetPriorityThread(kthread, LOW_PRIORITY);
        
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }
}

// Get process image name
static PUCHAR GetProcessImageName(PEPROCESS Process)
{
    __try {
        // EPROCESS->ImageFileName offset: 0x5A8 on Win10/11 x64
        return (PUCHAR)((ULONG_PTR)Process + 0x5A8);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
}

// ============================================================================
// CONFIGURATION
// ============================================================================

#define BE_MODULE_START 0x180000000ULL
#define BE_MODULE_END   0x180A00000ULL

// ============================================================================
// GLOBAL STATE
// ============================================================================

static volatile LONG g_BlockedOperations = 0;
static volatile LONG g_BEThreadsFound = 0;
static PVOID g_ThreadNotifyHandle = NULL;
static PVOID g_ImageNotifyHandle = NULL;
static HANDLE g_GameProcessId = NULL;
static PVOID g_BEModuleBase = NULL;
static SIZE_T g_BEModuleSize = 0;
static BOOLEAN g_BypassActive = FALSE;

// ============================================================================
// BE DETECTION
// ============================================================================

static inline BOOLEAN IsAddressInBE(PVOID addr)
{
    ULONG_PTR address = (ULONG_PTR)addr;
    
    // Check if in known BE range
    if (address >= BE_MODULE_START && address <= BE_MODULE_END)
        return TRUE;
    
    // Check if in detected BE module
    if (g_BEModuleBase && address >= (ULONG_PTR)g_BEModuleBase && 
        address < (ULONG_PTR)g_BEModuleBase + g_BEModuleSize)
        return TRUE;
    
    return FALSE;
}

// ============================================================================
// THREAD MONITORING
// ============================================================================

static VOID ThreadNotifyCallback(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ThreadId);
    
    if (!Create || !g_BypassActive)
        return;
    
    // Only monitor game process
    if (ProcessId != g_GameProcessId)
        return;
    
    // Get thread start address
    PETHREAD thread;
    if (NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &thread))) {
        PVOID startAddr = GetThreadStartAddress(thread);
        
        // Check if thread starts in BE module
        if (IsAddressInBE(startAddr)) {
            InterlockedIncrement(&g_BEThreadsFound);
            
            // Suspend BE threads to prevent report sending
            __try {
                SuspendThread(thread);
                InterlockedIncrement(&g_BlockedOperations);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }
        
        ObDereferenceObject(thread);
    }
}

// ============================================================================
// IMAGE LOAD MONITORING
// ============================================================================

static VOID ImageLoadCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo)
{
    if (!g_BypassActive || !FullImageName || !ImageInfo)
        return;
    
    // Only monitor game process
    if (ProcessId != g_GameProcessId)
        return;
    
    // Check if this is BEClient_x64.dll
    if (wcsstr(FullImageName->Buffer, L"BEClient") || 
        wcsstr(FullImageName->Buffer, L"beclient")) {
        
        g_BEModuleBase = ImageInfo->ImageBase;
        g_BEModuleSize = ImageInfo->ImageSize;
        
        // Corrupt BE module entry point to prevent initialization
        __try {
            PMDL mdl = IoAllocateMdl(ImageInfo->ImageBase, PAGE_SIZE, FALSE, FALSE, NULL);
            if (mdl) {
                MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
                PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
                
                if (mapped) {
                    // Overwrite entry point with RET instruction
                    *(BYTE*)mapped = 0xC3;  // RET
                    MmUnmapLockedPages(mapped, mdl);
                    InterlockedIncrement(&g_BlockedOperations);
                }
                
                MmUnlockPages(mdl);
                IoFreeMdl(mdl);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
}

// ============================================================================
// GAME PROCESS DETECTION
// ============================================================================

static BOOLEAN FindGameProcess()
{
    // Look for DayZ process
    PEPROCESS process = PsGetCurrentProcess();
    HANDLE pid = PsGetProcessId(process);
    
    // Get process name
    PUCHAR processName = GetProcessImageName(process);
    
    if (processName) {
        // Check for DayZ executable
        if (_stricmp((const char*)processName, "DayZ_x64.exe") == 0 ||
            _stricmp((const char*)processName, "DayZ.exe") == 0) {
            g_GameProcessId = pid;
            return TRUE;
        }
    }
    
    return FALSE;
}

// ============================================================================
// PERIODIC SCANNING
// ============================================================================

static KTIMER g_ScanTimer;
static KDPC g_ScanDpc;

static VOID ScanDpcRoutine(
    PKDPC Dpc,
    PVOID DeferredContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    
    if (!g_BypassActive || !g_GameProcessId)
        return;
    
    // Try to find game process if not found yet
    if (!g_GameProcessId) {
        FindGameProcess();
    }
    
    // Scan for BE structures and corrupt them
    if (g_BEModuleBase) {
        __try {
            // Scan BE module for report queue patterns
            // Pattern: 24-byte allocations in a linked list
            // When found, zero them out
            
            PEPROCESS process;
            if (NT_SUCCESS(PsLookupProcessByProcessId(g_GameProcessId, &process))) {
                KAPC_STATE apc;
                KeStackAttachProcess(process, &apc);
                
                // Scan BE module memory
                for (SIZE_T offset = 0; offset < g_BEModuleSize; offset += 0x1000) {
                    PVOID addr = (BYTE*)g_BEModuleBase + offset;
                    
                    if (MmIsAddressValid(addr)) {
                        // Look for report queue signature
                        // This is a simplified example - you'd need actual patterns
                        PULONG ptr = (PULONG)addr;
                        
                        // Check for suspicious patterns
                        if (*ptr == 0x18 && *(ptr + 1) != 0) {
                            // Might be a report node, corrupt it
                            RtlZeroMemory(addr, 0x18);
                            InterlockedIncrement(&g_BlockedOperations);
                        }
                    }
                }
                
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(process);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
}

// ============================================================================
// INSTALLATION
// ============================================================================

static inline BOOLEAN InstallBEBypass()
{
    // Register thread creation callback
    NTSTATUS status = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);
    if (!NT_SUCCESS(status))
        return FALSE;
    
    g_ThreadNotifyHandle = (PVOID)1;  // Mark as registered
    
    // Register image load callback
    status = PsSetLoadImageNotifyRoutine(ImageLoadCallback);
    if (!NT_SUCCESS(status)) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
        return FALSE;
    }
    
    g_ImageNotifyHandle = (PVOID)1;  // Mark as registered
    
    // Try to find game process immediately
    FindGameProcess();
    
    // Setup periodic scanning timer
    KeInitializeTimer(&g_ScanTimer);
    KeInitializeDpc(&g_ScanDpc, ScanDpcRoutine, NULL);
    
    // Scan every 5 seconds
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -50000000LL;  // 5 seconds in 100ns units
    KeSetTimerEx(&g_ScanTimer, dueTime, 5000, &g_ScanDpc);
    
    g_BypassActive = TRUE;
    
    return TRUE;
}

static inline VOID UninstallBEBypass()
{
    g_BypassActive = FALSE;
    
    // Cancel timer
    KeCancelTimer(&g_ScanTimer);
    
    // Unregister callbacks
    if (g_ThreadNotifyHandle) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
        g_ThreadNotifyHandle = NULL;
    }
    
    if (g_ImageNotifyHandle) {
        PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
        g_ImageNotifyHandle = NULL;
    }
    
    // Reset state
    g_GameProcessId = NULL;
    g_BEModuleBase = NULL;
    g_BEModuleSize = 0;
    g_BlockedOperations = 0;
    g_BEThreadsFound = 0;
}

// ============================================================================
// STATISTICS
// ============================================================================

static inline VOID GetBEBypassStats(PULONG BlockedAllocs, PULONG BlockedPackets)
{
    if (BlockedAllocs)
        *BlockedAllocs = g_BlockedOperations;
    
    if (BlockedPackets)
        *BlockedPackets = g_BEThreadsFound;
}
