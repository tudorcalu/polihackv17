#include "hkRtlGetFullPathName_U.h"
#include <thread>

RtlPrototype RtlOriginal = nullptr;

BOOL __stdcall RtlHook(PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName) {
    std::wcout << L"\n[HOOK] RtlGetFullPathName_U call detected!" << std::endl;
    std::wcout << L"[HOOK] Intruder path: " << FileName << std::endl;

    std::wstring filePath(FileName);

    // Check if the path contains "ACInternal"
    if (filePath.find(L"ACInternal") != std::wstring::npos) {
        std::thread([]() {
            // Delay execution to allow game initialization to complete
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            const char* command =
                "wsl -u dan bash -lc \"cd /mnt/c/LLM4Decompile && conda activate llm4decompile && python3 main.py ACInternal.dll\"";
            system(command);
            }).detach();
    }



    return RtlOriginal(FileName, Size, Buffer, ShortName);
}

void InitRtlPathHook()
{
	std::cout << "[+] Initiated hook for: RtlGetFullPathName_U" << std::endl;

	HMODULE hModule = LoadLibraryA("ntdll.dll");

	RtlPrototype origFunAddr = (RtlPrototype) GetProcAddress(hModule, "RtlGetFullPathName_U");

	RtlOriginal = (RtlPrototype)(Trampoline( (PBYTE) origFunAddr, (PBYTE) RtlHook, 5));
}
