#pragma once
#include "definitions.h"

// Anti-Analysis & Anti-Debugging System
//
// FEATURES:
// 1. VM detection
// 2. Debugger detection
// 3. Analysis tool detection
// 4. Timing-based detection
// 5. Self-destruct on detection

// ============================================================================
// VM DETECTION
// ============================================================================

static BOOLEAN IsRunningInVM()
{
    BOOLEAN isVM = FALSE;

    // Check 1: CPUID hypervisor bit
    __try {
        int cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, 1);
        
        // Bit 31 of ECX indicates hypervisor presence
        if (cpuInfo[2] & (1 << 31)) {
            isVM = TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    // Check 2: Known VM vendor strings
    __try {
        int cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, 0x40000000);
        
        char vendor[13] = { 0 };
        *(int*)(vendor + 0) = cpuInfo[1];
        *(int*)(vendor + 4) = cpuInfo[2];
        *(int*)(vendor + 8) = cpuInfo[3];
        
        // Known VM signatures
        const char* vmSignatures[] = {
            "VMwareVMware",  // VMware
            "Microsoft Hv",  // Hyper-V
            "KVMKVMKVM",     // KVM
            "XenVMMXenVMM",  // Xen
            "prl hyperv",    // Parallels
            "VBoxVBoxVBox"   // VirtualBox
        };
        
        for (int i = 0; i < sizeof(vmSignatures) / sizeof(char*); i++) {
            if (memcmp(vendor, vmSignatures[i], 12) == 0) {
                isVM = TRUE;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    // Check 3: Timing-based detection
    __try {
        LARGE_INTEGER start, end, freq;
        KeQueryPerformanceCounter(&freq);
        
        start = KeQueryPerformanceCounter(NULL);
        // Small delay
        for (volatile int i = 0; i < 1000; i++);
        end = KeQueryPerformanceCounter(NULL);
        
        LONGLONG elapsed = end.QuadPart - start.QuadPart;
        LONGLONG elapsedMs = (elapsed * 1000) / freq.QuadPart;
        
        // VMs typically have timing inconsistencies
        if (elapsedMs > 100) {  // Should be < 1ms on real hardware
            isVM = TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    return isVM;
}

// ============================================================================
// DEBUGGER DETECTION
// ============================================================================

static BOOLEAN IsKernelDebuggerPresent()
{
    // Check KdDebuggerEnabled
    if (*KdDebuggerEnabled) {
        return TRUE;
    }

    // Check KdDebuggerNotPresent
    if (!*KdDebuggerNotPresent) {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN IsBeingDebugged()
{
    BOOLEAN detected = FALSE;

    // Check 1: Kernel debugger
    if (IsKernelDebuggerPresent()) {
        detected = TRUE;
    }

    // Check 2: Debug registers
    __try {
        ULONG_PTR dr0 = __readdr(0);
        ULONG_PTR dr1 = __readdr(1);
        ULONG_PTR dr2 = __readdr(2);
        ULONG_PTR dr3 = __readdr(3);
        ULONG_PTR dr7 = __readdr(7);
        
        // If any debug register is set, we're being debugged
        if (dr0 || dr1 || dr2 || dr3 || (dr7 & 0xFF)) {
            detected = TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    // Check 3: Timing-based detection
    __try {
        LARGE_INTEGER start = KeQueryPerformanceCounter(NULL);
        
        // Execute some instructions
        volatile int x = 0;
        for (int i = 0; i < 100; i++) {
            x += i;
        }
        
        LARGE_INTEGER end = KeQueryPerformanceCounter(NULL);
        LONGLONG elapsed = end.QuadPart - start.QuadPart;
        
        // Debuggers slow down execution significantly
        if (elapsed > 100000) {  // Threshold for debugger detection
            detected = TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    return detected;
}

// ============================================================================
// ANALYSIS TOOL DETECTION
// ============================================================================

static BOOLEAN IsAnalysisToolPresent()
{
    BOOLEAN detected = FALSE;

    // Check for known analysis drivers
    const WCHAR* analysisDrivers[] = {
        L"\\Driver\\WinDbg",
        L"\\Driver\\PROCEXP152",  // Process Explorer
        L"\\Driver\\PROCMON24",   // Process Monitor
        L"\\Driver\\Wireshark",
        L"\\Driver\\IDA",
        L"\\Driver\\OllyDbg",
        L"\\Driver\\x64dbg"
    };

    for (int i = 0; i < sizeof(analysisDrivers) / sizeof(WCHAR*); i++) {
        UNICODE_STRING driverName;
        RtlInitUnicodeString(&driverName, analysisDrivers[i]);
        
        PDRIVER_OBJECT driverObj = NULL;
        NTSTATUS status = ObReferenceObjectByName(
            &driverName,
            OBJ_CASE_INSENSITIVE,
            NULL,
            0,
            *IoDriverObjectType,
            KernelMode,
            NULL,
            (PVOID*)&driverObj
        );
        
        if (NT_SUCCESS(status)) {
            ObDereferenceObject(driverObj);
            detected = TRUE;
            break;
        }
    }

    return detected;
}

// ============================================================================
// MEMORY SCANNING DETECTION
// ============================================================================

static volatile LONG g_MemoryAccessCount = 0;
static volatile ULONG g_LastAccessTime = 0;

static BOOLEAN IsMemoryBeingScanned()
{
    LARGE_INTEGER perfCounter = KeQueryPerformanceCounter(NULL);
    ULONG currentTime = (ULONG)(perfCounter.QuadPart / 10000);  // Milliseconds
    
    InterlockedIncrement(&g_MemoryAccessCount);
    
    // Check if memory is being accessed too frequently
    if (currentTime - g_LastAccessTime < 100) {  // Less than 100ms
        if (g_MemoryAccessCount > 50) {  // More than 50 accesses
            return TRUE;  // Likely being scanned
        }
    } else {
        // Reset counter
        g_MemoryAccessCount = 0;
        g_LastAccessTime = currentTime;
    }
    
    return FALSE;
}

// ============================================================================
// SELF-DESTRUCT MECHANISM
// ============================================================================

static BOOLEAN g_SelfDestructTriggered = FALSE;

static VOID TriggerSelfDestruct()
{
    if (g_SelfDestructTriggered)
        return;

    g_SelfDestructTriggered = TRUE;

    // Option 1: Zero out driver code
    __try {
        extern PVOID g_DriverImageBase;
        extern ULONG g_DriverImageSize;
        
        if (g_DriverImageBase && g_DriverImageSize) {
            RtlZeroMemory(g_DriverImageBase, g_DriverImageSize);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    // Option 2: Unhook everything (if functions are available)
    // Note: These are defined in other headers, may not be linked
    // UninstallStealthHook();
    // UninstallBEBypassV2();

    // Option 3: Clear all traces
    extern BOOLEAN CleanAllTraces(PDRIVER_OBJECT);
    CleanAllTraces(NULL);
}

// ============================================================================
// ANTI-ANALYSIS CHECKS
// ============================================================================

static BOOLEAN PerformAntiAnalysisChecks()
{
    // Check for VM
    if (IsRunningInVM()) {
        return FALSE;  // Detected
    }

    // Check for debugger
    if (IsBeingDebugged()) {
        return FALSE;  // Detected
    }

    // Check for analysis tools
    if (IsAnalysisToolPresent()) {
        return FALSE;  // Detected
    }

    // Check for memory scanning
    if (IsMemoryBeingScanned()) {
        return FALSE;  // Detected
    }

    return TRUE;  // All clear
}

// ============================================================================
// PERIODIC ANTI-ANALYSIS MONITORING
// ============================================================================

static KTIMER g_AntiAnalysisTimer;
static KDPC g_AntiAnalysisDpc;
static BOOLEAN g_AntiAnalysisActive = FALSE;

static VOID AntiAnalysisDpcRoutine(
    PKDPC Dpc,
    PVOID DeferredContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    
    if (!g_AntiAnalysisActive)
        return;

    // Perform checks
    if (!PerformAntiAnalysisChecks()) {
        // Analysis detected - trigger self-destruct
        TriggerSelfDestruct();
        return;
    }

    // Schedule next check (every 30 seconds)
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -300000000LL;  // 30 seconds
    KeSetTimer(&g_AntiAnalysisTimer, dueTime, &g_AntiAnalysisDpc);
}

// ============================================================================
// INITIALIZATION
// ============================================================================

static BOOLEAN InitAntiAnalysis()
{
    // Perform initial checks
    if (!PerformAntiAnalysisChecks()) {
        return FALSE;  // Don't load if analysis detected
    }

    // Setup periodic monitoring
    KeInitializeTimer(&g_AntiAnalysisTimer);
    KeInitializeDpc(&g_AntiAnalysisDpc, AntiAnalysisDpcRoutine, NULL);
    
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -300000000LL;  // 30 seconds
    KeSetTimer(&g_AntiAnalysisTimer, dueTime, &g_AntiAnalysisDpc);
    
    g_AntiAnalysisActive = TRUE;
    
    return TRUE;
}

static VOID ShutdownAntiAnalysis()
{
    g_AntiAnalysisActive = FALSE;
    KeCancelTimer(&g_AntiAnalysisTimer);
}

// ============================================================================
// EXPORT FUNCTIONS
// ============================================================================

static inline BOOLEAN IsEnvironmentSafe()
{
    return PerformAntiAnalysisChecks();
}

static inline VOID EnableAntiAnalysis()
{
    InitAntiAnalysis();
}

static inline VOID DisableAntiAnalysis()
{
    ShutdownAntiAnalysis();
}
