#include "Trampoline.h"

/// <summary>
/// Move execution flow from original function -> hook function -> code cave -> original function.
/// Avoids hook recursion.
/// </summary>
/// <param name="source">original function</param>
/// <param name="destination">hook function</param>
/// <param name="byteLen">amount of bytes to steal</param>
/// <returns>jump back to original function</returns>
BYTE* Trampoline(PBYTE source, PBYTE destination, unsigned int byteLen)
{
    if (byteLen < 5) {
        std::cout << "[-] Trampoline Hook Activation: FAILED" << std::endl;
        std::cout << "[-] REASON: Need at least 5 bytes to call or jump address" << std::endl;
        return nullptr;
    }

    // Allocate memory for trampoline (code cave) + room for jump back (5 bytes)
    BYTE* trampoline = (BYTE*)VirtualAlloc(nullptr, byteLen + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Copy the original instructions to trampoline
    memcpy_s(trampoline, byteLen, source, byteLen);

    // Calculate return address (where we jump back to in the original function)
    uintptr_t returnAddr = (uintptr_t)(source + byteLen);

    // Add JMP back from trampoline to original function after overwritten bytes
    trampoline[byteLen] = 0xE9; // JMP opcode
    uintptr_t relJumpBack = returnAddr - ((uintptr_t)trampoline + byteLen) - 5;
    *(uintptr_t*)(trampoline + byteLen + 1) = relJumpBack;

    // Detour: overwrite original function
    DWORD oldProtect;
    VirtualProtect(source, byteLen, PAGE_EXECUTE_READWRITE, &oldProtect);

    source[0] = 0xE9; // JMP opcode
    uintptr_t relHook = (uintptr_t)destination - (uintptr_t)source - 5;
    *(uintptr_t*)(source + 1) = relHook;

    VirtualProtect(source, byteLen, oldProtect, &oldProtect);

    return trampoline;
}
