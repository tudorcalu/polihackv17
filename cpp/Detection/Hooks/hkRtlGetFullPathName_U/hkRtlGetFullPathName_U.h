#pragma once

#include "../Trampoline.h"
#include "../../Utility/Convertions.h"

typedef ULONG(__stdcall* RtlPrototype)(PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName);

BOOL __stdcall RtlHook(PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName);

void InitRtlPathHook();
