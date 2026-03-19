#pragma once
#include "definitions.h"

// Disable unreferenced function warnings for this header
#pragma warning(push)
#pragma warning(disable: 4505)  // unreferenced function with internal linkage
#pragma warning(disable: 4100)  // unreferenced formal parameter

// Code Obfuscation System
//
// FEATURES:
// 1. Control flow flattening
// 2. Junk code insertion
// 3. String encryption
// 4. Constant obfuscation
// 5. Function pointer obfuscation

// ============================================================================
// STRING ENCRYPTION
// ============================================================================

// Compile-time string encryption using XOR
#define OBFUSCATE_KEY 0xAB

template<int N>
struct ObfuscatedString {
    char data[N];
    
    constexpr ObfuscatedString(const char* str) : data{} {
        for (int i = 0; i < N; i++) {
            data[i] = str[i] ^ OBFUSCATE_KEY;
        }
    }
    
    void decrypt(char* out) const {
        for (int i = 0; i < N; i++) {
            out[i] = data[i] ^ OBFUSCATE_KEY;
        }
    }
};

// Macro to create encrypted string
#define OBFSTR(str) []() { \
    constexpr auto encrypted = ObfuscatedString<sizeof(str)>(str); \
    char decrypted[sizeof(str)] = {0}; \
    encrypted.decrypt(decrypted); \
    return decrypted; \
}()

// ============================================================================
// CONSTANT OBFUSCATION
// ============================================================================

// Obfuscate constants using arithmetic
#define OBFUSCATE_CONST(x) ((x ^ 0x5A5A5A5A) + 0x12345678 - 0x12345678) ^ 0x5A5A5A5A

// Runtime constant deobfuscation
static inline ULONG DeobfuscateConst(ULONG obfuscated)
{
    return ((obfuscated ^ 0x5A5A5A5A) + 0x12345678 - 0x12345678) ^ 0x5A5A5A5A;
}

// ============================================================================
// JUNK CODE GENERATION
// ============================================================================

// Insert junk code that does nothing but looks suspicious
#define JUNK_CODE_1() \
    do { \
        volatile int __junk = 0; \
        for (int __i = 0; __i < 10; __i++) { \
            __junk += __i * 2; \
            __junk ^= 0xDEADBEEF; \
        } \
    } while(0)

#define JUNK_CODE_2() \
    do { \
        volatile ULONG_PTR __junk = (ULONG_PTR)_ReturnAddress(); \
        __junk = (__junk << 3) ^ (__junk >> 5); \
        __junk += 0x13579BDF; \
    } while(0)

#define JUNK_CODE_3() \
    do { \
        LARGE_INTEGER __perf = KeQueryPerformanceCounter(NULL); \
        volatile ULONG __val = (ULONG)(__perf.QuadPart & 0xFFFFFFFF); \
        __val = (__val * 0x9E3779B9) ^ 0x6A09E667; \
    } while(0)

// Random junk code insertion
#define RANDOM_JUNK() \
    do { \
        ULONG __seed = (ULONG)(KeQueryPerformanceCounter(NULL).QuadPart & 0x3); \
        switch(__seed) { \
            case 0: JUNK_CODE_1(); break; \
            case 1: JUNK_CODE_2(); break; \
            case 2: JUNK_CODE_3(); break; \
            default: break; \
        } \
    } while(0)

// ============================================================================
// CONTROL FLOW FLATTENING
// ============================================================================

// Flatten control flow using state machine
#define BEGIN_FLATTEN() \
    ULONG __state = 0; \
    ULONG __next = 1; \
    while(__state != 0xFFFFFFFF) { \
        switch(__state) {

#define FLATTEN_BLOCK(id) \
        case id: \
            __state = __next; \
            RANDOM_JUNK();

#define FLATTEN_NEXT(id) \
            __next = id; \
            break;

#define END_FLATTEN() \
        default: \
            __state = 0xFFFFFFFF; \
            break; \
        } \
    }

// ============================================================================
// FUNCTION POINTER OBFUSCATION
// ============================================================================

typedef struct _OBFUSCATED_FUNCTION {
    ULONG_PTR EncryptedPointer;
    ULONG Key;
} OBFUSCATED_FUNCTION, *POBFUSCATED_FUNCTION;

static inline PVOID ObfuscateFunctionPointer(PVOID func)
{
    LARGE_INTEGER perfCounter = KeQueryPerformanceCounter(NULL);
    ULONG key = (ULONG)(perfCounter.QuadPart & 0xFFFFFFFF);
    
    POBFUSCATED_FUNCTION obf = (POBFUSCATED_FUNCTION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(OBFUSCATED_FUNCTION), 'fbsO');
    
    if (obf) {
        obf->EncryptedPointer = (ULONG_PTR)func ^ key;
        obf->Key = key;
    }
    
    return obf;
}

static inline PVOID DeobfuscateFunctionPointer(PVOID obfuscated)
{
    if (!obfuscated)
        return NULL;
    
    POBFUSCATED_FUNCTION obf = (POBFUSCATED_FUNCTION)obfuscated;
    return (PVOID)(obf->EncryptedPointer ^ obf->Key);
}

static inline VOID FreeFunctionPointer(PVOID obfuscated)
{
    if (obfuscated) {
        ExFreePoolWithTag(obfuscated, 'fbsO');
    }
}

// ============================================================================
// OPAQUE PREDICATES
// ============================================================================

// Always true predicate (but hard to analyze)
static inline BOOLEAN OpaqueTrue()
{
    LARGE_INTEGER perf = KeQueryPerformanceCounter(NULL);
    ULONG val = (ULONG)(perf.QuadPart & 0xFFFFFFFF);
    
    // (x * 2) % 2 == 0 is always true
    return ((val * 2) % 2) == 0;
}

// Always false predicate (but hard to analyze)
static inline BOOLEAN OpaqueFalse()
{
    LARGE_INTEGER perf = KeQueryPerformanceCounter(NULL);
    ULONG val = (ULONG)(perf.QuadPart & 0xFFFFFFFF);
    
    // (x * 2 + 1) % 2 == 0 is always false
    return ((val * 2 + 1) % 2) == 0;
}

// ============================================================================
// ANTI-DISASSEMBLY TRICKS
// ============================================================================

// Insert fake function boundaries (x64 compatible - no inline asm)
#define FAKE_FUNCTION_START() \
    do { \
        volatile int __fake = 0; \
        if (__fake) { \
            return; \
        } \
    } while(0)

#define FAKE_FUNCTION_END() \
    do { \
        volatile int __fake = 0; \
        if (__fake) { \
            return; \
        } \
    } while(0)

// ============================================================================
// EXAMPLE OBFUSCATED FUNCTION
// ============================================================================

// Example of how to use obfuscation
static NTSTATUS ObfuscatedMemoryRead(PVOID source, PVOID dest, SIZE_T size)
{
    // Insert junk code
    RANDOM_JUNK();
    
    // Use opaque predicates
    if (OpaqueTrue()) {
        // Flatten control flow
        BEGIN_FLATTEN()
        
        FLATTEN_BLOCK(1)
            if (!source || !dest || size == 0) {
                __next = 0xFFFFFFFF;
                break;
            }
        FLATTEN_NEXT(2)
        
        FLATTEN_BLOCK(2)
            __try {
                RtlCopyMemory(dest, source, size);
                __next = 3;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                __next = 0xFFFFFFFF;
            }
        FLATTEN_NEXT(3)
        
        FLATTEN_BLOCK(3)
            RANDOM_JUNK();
            __next = 0xFFFFFFFF;
        FLATTEN_NEXT(0xFFFFFFFF)
        
        END_FLATTEN()
        
        return STATUS_SUCCESS;
    }
    
    // This will never execute (opaque false)
    if (OpaqueFalse()) {
        return STATUS_UNSUCCESSFUL;
    }
    
    return STATUS_SUCCESS;
}

// ============================================================================
// MACRO HELPERS
// ============================================================================

// Obfuscate a simple if statement
#define OBFUSCATED_IF(condition, true_block, false_block) \
    do { \
        RANDOM_JUNK(); \
        if (OpaqueTrue()) { \
            if (condition) { \
                true_block \
            } else { \
                false_block \
            } \
        } \
        RANDOM_JUNK(); \
    } while(OpaqueFalse())

// Obfuscate a loop
#define OBFUSCATED_LOOP(init, condition, increment, body) \
    do { \
        init; \
        RANDOM_JUNK(); \
        while (OpaqueTrue() && (condition)) { \
            body \
            increment; \
            if (OpaqueFalse()) break; \
        } \
        RANDOM_JUNK(); \
    } while(OpaqueFalse())

// ============================================================================
// EXPORT MACROS
// ============================================================================

// Use these macros in your code for automatic obfuscation
#define OBFUSCATE_BEGIN() RANDOM_JUNK()
#define OBFUSCATE_END() RANDOM_JUNK()

#define OBFUSCATE_CALL(func, ...) \
    ({ \
        RANDOM_JUNK(); \
        auto __result = func(__VA_ARGS__); \
        RANDOM_JUNK(); \
        __result; \
    })

#pragma warning(pop)  // Restore warnings
