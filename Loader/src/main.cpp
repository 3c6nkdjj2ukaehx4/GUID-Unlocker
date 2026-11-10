// ============================================================================
//  Loader.exe
//
//  Injects version.dll into a running mxbikes.exe.
//  Closes immediately if the game is not open.
// ============================================================================

#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cwchar>
#include <string>

namespace {

constexpr const wchar_t* kProcessName = L"mxbikes.exe";
constexpr const wchar_t* kDllName     = L"version.dll";

DWORD FindProcessId(const wchar_t* name)
{
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe))
    {
        do
        {
            if (_wcsicmp(pe.szExeFile, name) == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

std::wstring LoaderDirectory()
{
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    wchar_t* slash = std::wcsrchr(path, L'\\');
    if (slash)
        *slash = L'\0';
    return path;
}

bool FileExists(const std::wstring& path)
{
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool InjectDll(HANDLE process, const std::wstring& dllPath)
{
    const SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(process, nullptr, bytes,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote)
        return false;

    bool ok = false;

    if (WriteProcessMemory(process, remote, dllPath.c_str(), bytes, nullptr))
    {
        HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
        auto loadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(kernel, "LoadLibraryW"));

        if (loadLibrary)
        {
            HANDLE thread = CreateRemoteThread(process, nullptr, 0, loadLibrary,
                                               remote, 0, nullptr);
            if (thread)
            {
                WaitForSingleObject(thread, 1000);

                DWORD exitCode = 0;
                GetExitCodeThread(thread, &exitCode);
                ok = exitCode != 0;

                CloseHandle(thread);
            }
        }
    }

    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return ok;
}

bool InjectIntoProcess(DWORD pid, const std::wstring& dllPath)
{
    HANDLE process = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);

    if (!process)
        return false;

    const bool ok = InjectDll(process, dllPath);
    CloseHandle(process);
    return ok;
}

void KeepOpenFor3s(ULONGLONG start)
{
    const ULONGLONG elapsed = GetTickCount64() - start;
    if (elapsed < 3000)
        Sleep(static_cast<DWORD>(3000 - elapsed));
}

} // namespace

int wmain()
{
    const ULONGLONG start = GetTickCount64();

    std::wprintf(L"Made by @7h5qha6xrdn65psk\n");

    const std::wstring dllPath = LoaderDirectory() + L"\\" + kDllName;
    if (!FileExists(dllPath))
    {
        std::wprintf(L"Failed.\n");
        return 1;
    }

    const DWORD pid = FindProcessId(kProcessName);
    if (!pid)
    {
        std::wprintf(L"Failed.\n");
        return 1;
    }

    std::wprintf(L"Injecting...\n");
    if (!InjectIntoProcess(pid, dllPath))
    {
        std::wprintf(L"Failed.\n");
        return 1;
    }

    std::wprintf(L"Reloading tracks...\n");
    std::wprintf(L"Success\n");

    KeepOpenFor3s(start);
    return 0;
}
