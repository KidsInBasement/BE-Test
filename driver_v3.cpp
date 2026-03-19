#include "driver.h"
#include "hook.h"
#include "cleaner.h"
#include "be_bypass_v2.h"
#include "stealth_hook.h"
#include "secure_comm.h"
#include "anti_analysis.h"
#include "code_obfuscation.h"
#include "be_report_scanner.h"

// BattleEye Bypass Driver V3 - Full Stealth Edition
//
// HIGH PRIORITY (V2):
// ✅ Dynamic offset resolution
// ✅ Encrypted communication
// ✅ Randomized timing
// ✅ Polymorphic hooks
// ✅ Hash-based detection
//
// MEDIUM PRIORITY (V3):
// ✅ Anti-analysis checks
// ✅ Code obfuscation
// ✅ Better BE report scanning
// ✅ Self-destruct on detection

// Global driver state
PVOID g_DriverImageBase = NULL;
ULONG g_DriverImageSize = 0;

static NTSTATUS RealEntryV3(PDRIVER_OBJECT DriverObject)
{
    OBFUSCATE_BEGIN();
    
    // Save driver image info for self-destruct
    if (DriverObject) {
        g_DriverImageBase = DriverObject->DriverStart;
        g_DriverImageSize = DriverObject->DriverSize;
    }
    
    // CRITICAL: Perform anti-analysis checks FIRST
    if (!IsEnvironmentSafe()) {
        // Analysis detected - abort loading
        return STATUS_UNSUCCESSFUL;
    }
    
    RANDOM_JUNK();
    
    // Initialize secure communication
    InitSecureComm();
    
    RANDOM_JUNK();
    
    // Install syscall hook with stealth improvements
    OBFUSCATED_IF(
        !InstallStealthHook(NULL, &Hook::Handler),
        {
            // Fallback to original hook method
            if (!Hook::Install(&Hook::Handler)) {
                return STATUS_UNSUCCESSFUL;
            }
        },
        {}
    );
    
    RANDOM_JUNK();

    // Clean driver traces from PiDDB and MmUnloadedDrivers
    CleanAllTraces(DriverObject);
    
    RANDOM_JUNK();

    // Install improved BattleEye bypass (V2 with stealth features)
    if (!InstallBEBypassV2()) {
        // Non-fatal - driver still works for memory access
    }
    
    RANDOM_JUNK();
    
    // Enable anti-analysis monitoring
    EnableAntiAnalysis();
    
    OBFUSCATE_END();

    return STATUS_SUCCESS;
}

// Obfuscated driver entry point
extern "C" NTSTATUS DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    
    // Use control flow flattening
    BEGIN_FLATTEN()
    
    FLATTEN_BLOCK(1)
        // Perform initial anti-analysis check
        if (!PerformAntiAnalysisChecks()) {
            status = STATUS_UNSUCCESSFUL;
            __next = 0xFFFFFFFF;  // Abort
            break;
        }
    FLATTEN_NEXT(2)
    
    FLATTEN_BLOCK(2)
        // Call real entry point
        status = RealEntryV3(DriverObject);
        if (!NT_SUCCESS(status)) {
            __next = 0xFFFFFFFF;  // Abort
            break;
        }
    FLATTEN_NEXT(3)
    
    FLATTEN_BLOCK(3)
        // Success
        status = STATUS_SUCCESS;
        __next = 0xFFFFFFFF;
    FLATTEN_NEXT(0xFFFFFFFF)
    
    END_FLATTEN()
    
    return status;
}

// Obfuscated unload routine (if needed)
extern "C" VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    
    OBFUSCATE_BEGIN();
    
    // Disable anti-analysis
    DisableAntiAnalysis();
    
    // Uninstall BE bypass
    UninstallBEBypassV2();
    
    // Uninstall hooks
    UninstallStealthHook();
    
    // Clean traces one more time
    CleanAllTraces(DriverObject);
    
    OBFUSCATE_END();
}
