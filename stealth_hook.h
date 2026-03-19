#pragma once
#include "definitions.h"

// Stealth Hook System
//
// IMPROVEMENTS:
// 1. Better PTE manipulation with validation
// 2. Anti-detection measures
// 3. Hook integrity checking
// 4. Polymorphic hook code

// ============================================================================
// HOOK VALIDATION
// ============================================================================

typedef struct _HOOK_INFO {
    PVOID OriginalFunction;
    PVOID HookFunction;
    BYTE OriginalBytes[16];
    ULONG_PTR OriginalPfn;
    ULONG_PTR HookedPfn;
    BOOLEAN Active;
    ULONG InstallTime;
    ULONG LastCheck;
} HOOK_INFO, *PHOOK_INFO;

static HOOK_INFO g_HookInfo = { 0 };

// ============================================================================
// ANTI-DETECTION: POLYMORPHIC HOOK CODE
// ============================================================================

// Generate different hook trampolines each time
static BOOLEAN GeneratePolymorphicTrampoline(PVOID target, PVOID handler, PBYTE outBuffer, PULONG outSize)
{
    if (!target || !handler || !outBuffer || !outSize)
        return FALSE;

    // Get random seed for polymorphism
    LARGE_INTEGER perfCounter = KeQueryPerformanceCounter(NULL);
    ULONG seed = (ULONG)(perfCounter.QuadPart & 0xFF);

    ULONG offset = 0;

    // Add random NOP sled (1-3 NOPs)
    ULONG nopCount = (seed % 3) + 1;
    for (ULONG i = 0; i < nopCount; i++) {
        outBuffer[offset++] = 0x90;  // NOP
    }

    // MOV RAX, handler (polymorphic)
    if (seed & 1) {
        // Variant 1: Direct MOV
        outBuffer[offset++] = 0x48;  // REX.W
        outBuffer[offset++] = 0xB8;  // MOV RAX, imm64
        *(PVOID*)(outBuffer + offset) = handler;
        offset += 8;
    } else {
        // Variant 2: XOR + ADD (more complex)
        outBuffer[offset++] = 0x48;  // REX.W
        outBuffer[offset++] = 0x31;  // XOR RAX, RAX
        outBuffer[offset++] = 0xC0;
        outBuffer[offset++] = 0x48;  // REX.W
        outBuffer[offset++] = 0xB8;  // MOV RAX, imm64
        *(PVOID*)(outBuffer + offset) = handler;
        offset += 8;
    }

    // JMP RAX (polymorphic)
    if (seed & 2) {
        // Variant 1: Direct JMP
        outBuffer[offset++] = 0xFF;  // JMP RAX
        outBuffer[offset++] = 0xE0;
    } else {
        // Variant 2: PUSH + RET
        outBuffer[offset++] = 0x50;  // PUSH RAX
        outBuffer[offset++] = 0xC3;  // RET
    }

    *outSize = offset;
    return TRUE;
}

// ============================================================================
// IMPROVED PTE HOOK WITH VALIDATION
// ============================================================================

static BOOLEAN InstallStealthPteHook(PVOID targetFunction, PVOID hookHandler)
{
    if (!targetFunction || !hookHandler)
        return FALSE;

    // Save original bytes
    __try {
        RtlCopyMemory(g_HookInfo.OriginalBytes, targetFunction, 16);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    // Generate polymorphic trampoline
    BYTE trampoline[32] = { 0 };
    ULONG trampolineSize = 0;
    if (!GeneratePolymorphicTrampoline(targetFunction, hookHandler, trampoline, &trampolineSize))
        return FALSE;

    // Install the hook using PTE manipulation
    // (Reuse existing PTE hook code from pte_hook.h)
    extern BOOLEAN InstallPteHook(PVOID target, PVOID handler);
    if (!InstallPteHook(targetFunction, hookHandler)) {
        // Fallback to direct write
        extern BOOL WriteReadOnlyMemory(PVOID dest, PVOID src, SIZE_T size);
        WriteReadOnlyMemory(targetFunction, trampoline, trampolineSize);
    }

    // Save hook info
    g_HookInfo.OriginalFunction = targetFunction;
    g_HookInfo.HookFunction = hookHandler;
    g_HookInfo.Active = TRUE;
    g_HookInfo.InstallTime = (ULONG)(KeQueryPerformanceCounter(NULL).QuadPart & 0xFFFFFFFF);
    g_HookInfo.LastCheck = g_HookInfo.InstallTime;

    return TRUE;
}

// ============================================================================
// HOOK INTEGRITY CHECKING
// ============================================================================

static BOOLEAN ValidateHookIntegrity()
{
    if (!g_HookInfo.Active || !g_HookInfo.OriginalFunction)
        return FALSE;

    __try {
        // Check if hook is still in place
        PBYTE current = (PBYTE)g_HookInfo.OriginalFunction;
        
        // Simple check: first byte should not match original
        if (current[0] == g_HookInfo.OriginalBytes[0] &&
            current[1] == g_HookInfo.OriginalBytes[1]) {
            // Hook was removed! Re-install
            return FALSE;
        }

        g_HookInfo.LastCheck = (ULONG)(KeQueryPerformanceCounter(NULL).QuadPart & 0xFFFFFFFF);
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

// ============================================================================
// ANTI-DETECTION: TIMING CHECKS
// ============================================================================

static BOOLEAN IsHookBeingScanned()
{
    // Detect if someone is scanning our hook
    // Check for suspicious timing patterns
    
    ULONG currentTime = (ULONG)(KeQueryPerformanceCounter(NULL).QuadPart & 0xFFFFFFFF);
    ULONG timeSinceInstall = currentTime - g_HookInfo.InstallTime;
    ULONG timeSinceCheck = currentTime - g_HookInfo.LastCheck;

    // If hook is being checked very frequently, might be under analysis
    if (timeSinceCheck < 100 && timeSinceInstall > 10000) {
        return TRUE;  // Suspicious activity
    }

    return FALSE;
}

// ============================================================================
// HOOK REMOVAL
// ============================================================================

static VOID RemoveStealthHook()
{
    if (!g_HookInfo.Active || !g_HookInfo.OriginalFunction)
        return;

    __try {
        // Restore original bytes
        extern BOOL WriteReadOnlyMemory(PVOID dest, PVOID src, SIZE_T size);
        WriteReadOnlyMemory(g_HookInfo.OriginalFunction, g_HookInfo.OriginalBytes, 16);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    RtlZeroMemory(&g_HookInfo, sizeof(HOOK_INFO));
}

// ============================================================================
// EXPORT FUNCTIONS
// ============================================================================

static inline BOOLEAN InstallStealthHook(PVOID target, PVOID handler)
{
    return InstallStealthPteHook(target, handler);
}

static inline BOOLEAN CheckHookHealth()
{
    if (IsHookBeingScanned()) {
        // Under analysis - might want to remove hook temporarily
        return FALSE;
    }
    
    return ValidateHookIntegrity();
}

static inline VOID UninstallStealthHook()
{
    RemoveStealthHook();
}
