# Compiler Crash Fix Instructions

## Problem
The Visual Studio compiler crashes with error -1073740791 (STATUS_STACK_BUFFER_OVERRUN) because there are TOO MANY header files with static inline functions:

- physical_memory.h: 10+ static inline functions
- pte_hook.h: 6+ static inline functions  
- iat_hook.h: 7+ static inline functions
- network_block.h: 7+ static inline functions
- be_bypass.h: 5+ static inline functions
- hwid_spoof.h: 6+ static inline functions
- spoof_call.h: 4+ static inline functions
- timing_bypass.h: 2+ static inline functions

When driver.cpp includes all these headers, the compiler tries to inline ALL of these functions and exhausts its stack.

## Solution Options

### Option 1: Remove `static` keyword (QUICK FIX)
Change all `static NTSTATUS FunctionName()` to just `inline NTSTATUS FunctionName()` in all header files.
This allows the linker to merge duplicate definitions instead of forcing separate copies.

### Option 2: Refactor all headers (PROPER FIX)
Split each large header into .h (declarations) and .cpp (implementations) like we did with:
- hwid_spoof_v2.h → hwid_spoof_v2.h + hwid_spoof_v2.cpp ✅
- cleaner.h → cleaner.h + cleaner.cpp ✅

Need to do the same for:
- physical_memory.h → physical_memory.h + physical_memory.cpp
- pte_hook.h → pte_hook.h + pte_hook.cpp
- iat_hook.h → iat_hook.h + iat_hook.cpp
- network_block.h → network_block.h + network_block.cpp
- be_bypass.h → be_bypass.h + be_bypass.cpp
- hwid_spoof.h → hwid_spoof.h + hwid_spoof.cpp
- spoof_call.h → spoof_call.h + spoof_call.cpp
- timing_bypass.h → timing_bypass.h + timing_bypass.cpp

### Option 3: Reduce optimization level
In Visual Studio project settings:
- Configuration Properties → C/C++ → Optimization
- Set "Optimization" to "Disabled (/Od)"
- Set "Inline Function Expansion" to "Disabled (/Ob0)"

This tells the compiler not to inline functions, reducing memory pressure.

## Recommended Approach
Try Option 3 first (quickest), then Option 1 if that doesn't work, then Option 2 if you need a proper long-term solution.
