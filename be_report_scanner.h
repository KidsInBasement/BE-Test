#pragma once
#include "definitions.h"

// Disable unreferenced function warnings for this header
#pragma warning(push)
#pragma warning(disable: 4505)  // unreferenced function with internal linkage

// BattleEye Report Structure Scanner
//
// FEATURES:
// 1. Pattern-based report queue detection
// 2. Memory signature scanning
// 3. Report corruption techniques
// 4. Network packet interception

// ============================================================================
// BE REPORT STRUCTURES (from IDA analysis)
// ============================================================================

// Based on BE_ANALYSIS_IDA.md findings:
// - BE uses 24-byte PagedPool allocations for report queue
// - Reports are linked in a queue structure
// - Each report has a type, size, and data pointer

#pragma pack(push, 1)
typedef struct _BE_REPORT_NODE {
    PVOID Next;           // +0x00: Next node in queue
    PVOID Prev;           // +0x08: Previous node in queue
    ULONG ReportType;     // +0x10: Type of report
    ULONG DataSize;       // +0x14: Size of report data
    PVOID DataPtr;        // +0x18: Pointer to report data
} BE_REPORT_NODE, *PBE_REPORT_NODE;
#pragma pack(pop)

// Report types (observed from analysis)
#define BE_REPORT_DRIVER_LOAD    0x01
#define BE_REPORT_MEMORY_ACCESS  0x02
#define BE_REPORT_PROCESS_INFO   0x03
#define BE_REPORT_MODULE_INFO    0x04
#define BE_REPORT_CALLBACK_INFO  0x05

// ============================================================================
// PATTERN SIGNATURES
// ============================================================================

// Signature for BE report queue head
static const UCHAR BE_QUEUE_HEAD_PATTERN[] = {
    0x48, 0x8B, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC,  // mov rcx, [rip+offset]
    0x48, 0x85, 0xC9,                          // test rcx, rcx
    0x74, 0xCC,                                // jz short
    0x48, 0x8B, 0x01                           // mov rax, [rcx]
};

// Signature for ExAllocatePool2 call in BE
static const UCHAR BE_ALLOC_PATTERN[] = {
    0x48, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,  // mov/lea
    0xBA, 0x18, 0x00, 0x00, 0x00,              // mov edx, 0x18 (24 bytes)
    0xE8, 0xCC, 0xCC, 0xCC, 0xCC               // call ExAllocatePool2
};

// Signature for report send function
static const UCHAR BE_SEND_PATTERN[] = {
    0x48, 0x89, 0x5C, 0x24, 0xCC,              // mov [rsp+XX], rbx
    0x48, 0x89, 0x74, 0x24, 0xCC,              // mov [rsp+XX], rsi
    0x57,                                       // push rdi
    0x48, 0x83, 0xEC, 0xCC,                    // sub rsp, XX
    0x48, 0x8B, 0xF9                           // mov rdi, rcx
};

// ============================================================================
// MEMORY SCANNING
// ============================================================================

static BOOLEAN ScanMemoryForPattern(
    PVOID baseAddress,
    SIZE_T size,
    const UCHAR* pattern,
    SIZE_T patternSize,
    PVOID* foundAddress)
{
    if (!baseAddress || !pattern || !foundAddress)
        return FALSE;

    __try {
        for (SIZE_T i = 0; i < size - patternSize; i++) {
            BOOLEAN match = TRUE;
            
            for (SIZE_T j = 0; j < patternSize; j++) {
                if (pattern[j] == 0xCC)  // Wildcard
                    continue;
                
                if (((PUCHAR)baseAddress)[i + j] != pattern[j]) {
                    match = FALSE;
                    break;
                }
            }
            
            if (match) {
                *foundAddress = (PUCHAR)baseAddress + i;
                return TRUE;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return FALSE;
}

// ============================================================================
// REPORT QUEUE DETECTION
// ============================================================================

static PVOID g_BEReportQueueHead = NULL;
static PVOID g_BESendFunction = NULL;

static BOOLEAN FindBEReportQueue(PVOID beModuleBase, SIZE_T beModuleSize)
{
    if (!beModuleBase || beModuleSize == 0)
        return FALSE;

    PVOID queuePattern = NULL;
    if (ScanMemoryForPattern(beModuleBase, beModuleSize,
        BE_QUEUE_HEAD_PATTERN, sizeof(BE_QUEUE_HEAD_PATTERN), &queuePattern)) {
        
        // Extract RIP-relative address
        __try {
            PUCHAR patternAddr = (PUCHAR)queuePattern;
            LONG offset = *(PLONG)(patternAddr + 3);
            g_BEReportQueueHead = (PVOID)(patternAddr + 7 + offset);
            return TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }

    return FALSE;
}

static BOOLEAN FindBESendFunction(PVOID beModuleBase, SIZE_T beModuleSize)
{
    if (!beModuleBase || beModuleSize == 0)
        return FALSE;

    PVOID sendPattern = NULL;
    if (ScanMemoryForPattern(beModuleBase, beModuleSize,
        BE_SEND_PATTERN, sizeof(BE_SEND_PATTERN), &sendPattern)) {
        
        g_BESendFunction = sendPattern;
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// REPORT CORRUPTION
// ============================================================================

static LONG g_CorruptedReports = 0;

static BOOLEAN CorruptReportNode(PBE_REPORT_NODE node)
{
    if (!node || !MmIsAddressValid(node))
        return FALSE;

    __try {
        // Method 1: Zero out the node
        RtlZeroMemory(node, sizeof(BE_REPORT_NODE));
        
        InterlockedIncrement(&g_CorruptedReports);
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

static BOOLEAN CorruptReportData(PBE_REPORT_NODE node)
{
    if (!node || !MmIsAddressValid(node))
        return FALSE;

    __try {
        // Corrupt the data pointer
        if (node->DataPtr && MmIsAddressValid(node->DataPtr)) {
            RtlZeroMemory(node->DataPtr, node->DataSize);
        }
        
        // Corrupt the node metadata
        node->ReportType = 0xFFFFFFFF;
        node->DataSize = 0;
        node->DataPtr = NULL;
        
        InterlockedIncrement(&g_CorruptedReports);
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

// ============================================================================
// QUEUE WALKING AND CORRUPTION
// ============================================================================

static VOID CorruptReportQueue()
{
    if (!g_BEReportQueueHead || !MmIsAddressValid(g_BEReportQueueHead))
        return;

    __try {
        PBE_REPORT_NODE head = *(PBE_REPORT_NODE*)g_BEReportQueueHead;
        if (!head || !MmIsAddressValid(head))
            return;

        PBE_REPORT_NODE current = head;
        int maxNodes = 100;  // Safety limit
        
        while (current && maxNodes-- > 0) {
            if (!MmIsAddressValid(current))
                break;

            PBE_REPORT_NODE next = (PBE_REPORT_NODE)current->Next;
            
            // Corrupt this node
            CorruptReportData(current);
            
            // Move to next
            current = next;
            
            // Avoid infinite loops
            if (current == head)
                break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

// ============================================================================
// POOL ALLOCATION MONITORING
// ============================================================================

static volatile LONG g_BlockedAllocations = 0;

// Monitor for 24-byte PagedPool allocations (BE report nodes)
static BOOLEAN IsLikelyBEAllocation(SIZE_T size, ULONG poolType)
{
    // BE uses 24-byte PagedPool allocations for report nodes
    // PagedPool = 1
    if (size == 24 && poolType == 1) {
        return TRUE;
    }
    
    return FALSE;
}

// ============================================================================
// ADVANCED SCANNING
// ============================================================================

static VOID ScanAndCorruptBEStructures(PVOID beModuleBase, SIZE_T beModuleSize)
{
    if (!beModuleBase || beModuleSize == 0)
        return;

    __try {
        // Scan for report queue patterns
        for (SIZE_T offset = 0; offset < beModuleSize; offset += 0x1000) {
            PVOID addr = (PUCHAR)beModuleBase + offset;
            
            if (!MmIsAddressValid(addr))
                continue;

            // Look for linked list patterns (Next/Prev pointers)
            PULONG_PTR ptr = (PULONG_PTR)addr;
            
            // Check if this looks like a report node
            if (ptr[0] > 0xFFFF800000000000ULL &&  // Next pointer in kernel space
                ptr[1] > 0xFFFF800000000000ULL &&  // Prev pointer in kernel space
                ptr[2] < 0x100 &&                   // Report type (small value)
                ptr[3] < 0x10000) {                 // Data size (reasonable)
                
                // Likely a report node - corrupt it
                PBE_REPORT_NODE node = (PBE_REPORT_NODE)addr;
                CorruptReportNode(node);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

static BOOLEAN InitBEReportScanner(PVOID beModuleBase, SIZE_T beModuleSize)
{
    if (!beModuleBase || beModuleSize == 0)
        return FALSE;

    // Find report queue
    FindBEReportQueue(beModuleBase, beModuleSize);
    
    // Find send function
    FindBESendFunction(beModuleBase, beModuleSize);
    
    return (g_BEReportQueueHead != NULL);
}

// ============================================================================
// PERIODIC SCANNING
// ============================================================================

static VOID PeriodicReportScan(PVOID beModuleBase, SIZE_T beModuleSize)
{
    // Corrupt report queue
    CorruptReportQueue();
    
    // Scan for new report structures
    ScanAndCorruptBEStructures(beModuleBase, beModuleSize);
}

// ============================================================================
// STATISTICS
// ============================================================================

static inline LONG GetCorruptedReportCount()
{
    return (LONG)g_CorruptedReports;
}

static inline LONG GetBlockedAllocationCount()
{
    return (LONG)g_BlockedAllocations;
}

static inline BOOLEAN IsReportQueueFound()
{
    return (g_BEReportQueueHead != NULL);
}

#pragma warning(pop)  // Restore warnings
