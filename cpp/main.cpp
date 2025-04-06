#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#include <iostream>
#include <wincrypt.h>
#include <fstream>
#include <vector>
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma warning(disable : 4996)
#define _CRT_SECURE_NO_WARNINGS

bool CalculateMD5(const TCHAR* filename, std::string& hashString)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE buffer[4096];
    DWORD bytesRead;
    BYTE rgbHash[16];
    DWORD cbHash = 16;

    HANDLE hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        return false;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return false;
    }

    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return false;
        }
    }

    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        char hexBuffer[33];
        for (DWORD i = 0; i < cbHash; ++i) {
            sprintf(&hexBuffer[i * 2], "%02x", rgbHash[i]);
        }
        hexBuffer[32] = '\0';
        hashString = hexBuffer;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return true;
}

void PrintProcessNameAndModulesWithHash(DWORD processID)
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

    if (hProcess != nullptr)
    {
        HMODULE hMods[1024];
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
        {
            GetModuleBaseName(hProcess, hMods[0], szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
            _tprintf(TEXT("\n%s (PID: %u)\n"), szProcessName, processID);

            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
            {
                TCHAR szModName[MAX_PATH];
                if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
                {
                    std::string md5hash;
                    if (CalculateMD5(szModName, md5hash))
                    {
                        _tprintf(TEXT("\t%s\n\t\tMD5: %hs [HASH OK]\n"), szModName, md5hash.c_str());
                    }
                    else
                    {
                        _tprintf(TEXT("\t%s\n\t\tMD5: <failed to compute>[HASH FAILED]\n"), szModName);
                    }
                }
            }
        }
        CloseHandle(hProcess);
    }
    else
    {
        _tprintf(TEXT("\n<Unable to open process> (PID: %u)\n"), processID);
    }
}

int main()
{
    // Define the PID or process name you want to filter
    DWORD targetPID = 1234;  // Example PID to search for
    TCHAR targetName[MAX_PATH] = TEXT("ac_client.exe");  // Example name to search for

    DWORD aProcesses[1024], cbNeeded;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        return 1;
    }

    DWORD cProcesses = cbNeeded / sizeof(DWORD);

    // Iterate through processes and filter by PID or name
    for (DWORD i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] == 0) continue;

        // Open process to check its name
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
        if (hProcess != nullptr)
        {
            TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
            if (GetModuleBaseName(hProcess, NULL, szProcessName, sizeof(szProcessName) / sizeof(TCHAR)))
            {
                // Check if the process name or PID matches the target values
                if (_tcscmp(szProcessName, targetName) == 0 || aProcesses[i] == targetPID)
                {
                    // If a match is found, print the process info
                    _tprintf(TEXT("Found matching process: %s (PID: %u)\n"), szProcessName, aProcesses[i]);
                    PrintProcessNameAndModulesWithHash(aProcesses[i]);
                }
            }
            CloseHandle(hProcess);
        }
    }

    return 0;
}
