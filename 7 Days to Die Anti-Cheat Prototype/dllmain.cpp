#include <windows.h>
#include <Shlwapi.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#pragma comment(lib, "Shlwapi.lib")

// -----------------------------------------------------------------------------
// XInput typedefs & pointers
// -----------------------------------------------------------------------------
typedef DWORD(WINAPI* XInputGetState_t)(DWORD, void*);
typedef DWORD(WINAPI* XInputSetState_t)(DWORD, void*);
typedef DWORD(WINAPI* XInputGetCapabilities_t)(DWORD, DWORD, void*);
typedef VOID(WINAPI* XInputEnable_t)(BOOL);
typedef DWORD(WINAPI* XInputGetDSoundAudioDeviceGuids_t)(DWORD, GUID*, GUID*);
typedef DWORD(WINAPI* XInputGetBatteryInformation_t)(DWORD, BYTE, void*);
typedef DWORD(WINAPI* XInputGetKeystroke_t)(DWORD, DWORD, void*);
typedef DWORD(WINAPI* XInputUnnamed100_t)();
typedef DWORD(WINAPI* XInputUnnamed101_t)();
typedef DWORD(WINAPI* XInputUnnamed102_t)();
typedef DWORD(WINAPI* XInputUnnamed103_t)();

static XInputGetState_t    pXInputGetState = nullptr;
static XInputSetState_t    pXInputSetState = nullptr;
static XInputGetCapabilities_t pXInputGetCaps = nullptr;
static XInputEnable_t      pXInputEnable = nullptr;
static XInputGetDSoundAudioDeviceGuids_t pXInputGetDSound = nullptr;
static XInputGetBatteryInformation_t pXInputGetBattery = nullptr;
static XInputGetKeystroke_t pXInputGetKeystroke = nullptr;
static XInputUnnamed100_t  pUnnamed100 = nullptr;
static XInputUnnamed101_t  pUnnamed101 = nullptr;
static XInputUnnamed102_t  pUnnamed102 = nullptr;
static XInputUnnamed103_t  pUnnamed103 = nullptr;

static HMODULE g_OriginalDll = nullptr;

// -----------------------------------------------------------------------------
// Known cheat exe names & window-title fragments
// -----------------------------------------------------------------------------
static const wchar_t* cheatExecutables[] = {
    L"wemod.exe", L"cheatengine.exe", L"ce-trainer.exe", L"artmoney.exe", L"flingtrainer.exe",
    L"megadev.exe", L"7daystrainer.exe", L"cheatevolution.exe", L"cheathappens.exe",
    L"mrantifun.exe", L"7daystodieearlyaccessplus.exe", L"7daystodietrainer.exe", L"plitch.exe",
    L"unknowncheats.exe",  L"gamecopyworld.exe", L"ggmania.exe",  L"7daystodieearlyaccessplus23trainer.exe", 
    L"7 Days to Die Early Access Plus 23 Trainer Updated 2024.02.18.exe" 
};

static const wchar_t* cheatWindowTitles[] = {
    L"7 Days to Die Trainer", L"WeMod", L"Cheat Engine",  L"Cheat Happens",  L"Cheat Evolution",
    L"FLiNG",  L"MegaTrainer", L"ArtMoney",  L"MrAntiFun",  L"UnknownCheats", L"GameCopyWorld",
    L"GGMania",  L"Early Access+",  L"Early Access Plus 23"
};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------
static std::wstring ToLower(const std::wstring& s) {
    std::wstring r = s;
    for (auto& c : r) c = towlower(c);
    return r;
}

static std::vector<std::wstring> GetRunningProcesses() {
    std::vector<std::wstring> procs;
    PROCESSENTRY32W pe{ sizeof(pe) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return procs;
    if (Process32FirstW(snap, &pe)) {
        do { procs.push_back(pe.szExeFile); } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return procs;
}

static void TerminatePid(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (h) {
        TerminateProcess(h, 0);
        CloseHandle(h);
    }
}

static void TerminateByName(const wchar_t* name) {
    PROCESSENTRY32W pe{ sizeof(pe) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                TerminatePid(pe.th32ProcessID);
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

// Show alert, kill trainer & schedule game exit in 5s
static void AlertAndExit(const std::wstring& detectedName, DWORD winPid = 0) {
    // 1- kill cheat immediately
    if (winPid) TerminatePid(winPid);
    else        TerminateByName(detectedName.c_str());

    // 2- schedule game exit in 5 seconds
    CreateThread(nullptr, 0, [](LPVOID) {
        Sleep(5000);
        ExitProcess(0);
        return DWORD(0);
        }, nullptr, 0, nullptr);

    // 3- show modal warning
    MessageBoxW(nullptr,
        (L"Cheat detected: " + detectedName + L"\n\nGame will close in 5 seconds.").c_str(),
        L"7 Days to Die - Anti-Cheat",  MB_ICONWARNING | MB_OK| MB_SYSTEMMODAL| MB_SETFOREGROUND );

    // 4- immediate exit if user clicks OK
    ExitProcess(0);
}

// -----------------------------------------------------------------------------
// Detection logic
// -----------------------------------------------------------------------------
static void DetectAndTerminateCheats() {
    auto procs = GetRunningProcesses();
    const std::wstring game1 = L"7daystodie.exe";
    const std::wstring game2 = L"7daystodie_eac.exe";

    // Generic keyword scan (skip game & this DLL)
    for (auto& p : procs) {
        auto low = ToLower(p);
        if (low == game1 || low == game2 || low == L"xinput1_3.dll")
            continue;
        for (auto& kw : { L"trainer", L"cheat", L"hack", L"inject", L"bot", L"editor" }) {
            if (low.find(kw) != std::wstring::npos) {
                AlertAndExit(p);
            }
        }
    }

    // Explicit exe list
    for (auto& exe : cheatExecutables) {
        auto target = ToLower(exe);
        for (auto& p : procs) {
            if (ToLower(p) == target) {
                AlertAndExit(p);
            }
        }
    }

    // Explicit window list
    EnumWindows([](HWND hwnd, LPARAM) {
        if (!IsWindowVisible(hwnd)) return TRUE;
        wchar_t buf[256];
        if (!GetWindowTextW(hwnd, buf, _countof(buf))) return TRUE;
        std::wstring title = buf, low = ToLower(title);
        for (auto& part : cheatWindowTitles) {
            if (low.find(ToLower(part)) != std::wstring::npos) {
                DWORD pid = 0;
                GetWindowThreadProcessId(hwnd, &pid);
                AlertAndExit(title, pid);
            }
        }
        return TRUE;
        }, 0);
}

// -----------------------------------------------------------------------------
// Monitor thread (periodic + VERIFY sequence)
// -----------------------------------------------------------------------------
static DWORD WINAPI MonitorThread(LPVOID) {
    Sleep(5000);
    const std::string trigger = "VERIFY";
    std::string recent;

    DetectAndTerminateCheats();

    while (true) {
        DetectAndTerminateCheats();

        for (int vk = 'A'; vk <= 'Z'; ++vk) {
            if (GetAsyncKeyState(vk) & 1) {
                recent.push_back((char)vk);
                if (recent.size() > trigger.size())
                    recent.erase(0, recent.size() - trigger.size());
                if (recent == trigger) {
                    MessageBeep(MB_ICONEXCLAMATION);
                    MessageBoxA(nullptr,"DLL Verified","Anti-Cheat DLL", MB_OK | MB_SYSTEMMODAL | MB_SETFOREGROUND);

                    recent.clear();
                }

            }
        }
        Sleep(50);
    }
    return 0;
}

// -----------------------------------------------------------------------------
// Load real XInput DLL & resolve exports
// -----------------------------------------------------------------------------
static BOOL LoadOriginal() {
    char path[MAX_PATH];
    if (!GetSystemDirectoryA(path, MAX_PATH)) return FALSE;
    strcat_s(path, "\\xinput1_3.dll");
    g_OriginalDll = LoadLibraryA(path);
    if (!g_OriginalDll) return FALSE;

    pXInputGetState = (XInputGetState_t)GetProcAddress(g_OriginalDll, "XInputGetState");
    pXInputSetState = (XInputSetState_t)GetProcAddress(g_OriginalDll, "XInputSetState");
    pXInputGetCaps = (XInputGetCapabilities_t)GetProcAddress(g_OriginalDll, "XInputGetCapabilities");
    pXInputEnable = (XInputEnable_t)GetProcAddress(g_OriginalDll, "XInputEnable");
    pXInputGetDSound = (XInputGetDSoundAudioDeviceGuids_t)GetProcAddress(g_OriginalDll, "XInputGetDSoundAudioDeviceGuids");
    pXInputGetBattery = (XInputGetBatteryInformation_t)GetProcAddress(g_OriginalDll, "XInputGetBatteryInformation");
    pXInputGetKeystroke = (XInputGetKeystroke_t)GetProcAddress(g_OriginalDll, "XInputGetKeystroke");
    pUnnamed100 = (XInputUnnamed100_t)GetProcAddress(g_OriginalDll, (LPCSTR)100);
    pUnnamed101 = (XInputUnnamed101_t)GetProcAddress(g_OriginalDll, (LPCSTR)101);
    pUnnamed102 = (XInputUnnamed102_t)GetProcAddress(g_OriginalDll, (LPCSTR)102);
    pUnnamed103 = (XInputUnnamed103_t)GetProcAddress(g_OriginalDll, (LPCSTR)103);

    return (pXInputGetState != nullptr);
}

static void FreeOriginal() {
    if (g_OriginalDll) {
        FreeLibrary(g_OriginalDll);
        g_OriginalDll = nullptr;
    }
}

// -----------------------------------------------------------------------------
// XInput export stubs
// -----------------------------------------------------------------------------
extern "C" {

    DWORD WINAPI XInputGetState(DWORD u, void* s) {
        if (!g_OriginalDll && !LoadOriginal()) return ERROR_DEVICE_NOT_CONNECTED;
        return pXInputGetState(u, s);
    }

    DWORD WINAPI XInputSetState(DWORD u, void* v) {
        if (!g_OriginalDll && !LoadOriginal()) return ERROR_DEVICE_NOT_CONNECTED;
        return pXInputSetState(u, v);
    }

    DWORD WINAPI XInputGetCapabilities(DWORD u, DWORD f, void* c) {
        if (!g_OriginalDll && !LoadOriginal()) return ERROR_DEVICE_NOT_CONNECTED;
        return pXInputGetCaps(u, f, c);
    }

    VOID WINAPI XInputEnable(BOOL e) {
        if (!g_OriginalDll && !LoadOriginal()) return;
        pXInputEnable(e);
    }

    DWORD WINAPI XInputGetDSoundAudioDeviceGuids(DWORD u, GUID* r, GUID* c) {
        if (!g_OriginalDll && !LoadOriginal()) return ERROR_DEVICE_NOT_CONNECTED;
        return pXInputGetDSound(u, r, c);
    }

    DWORD WINAPI XInputGetBatteryInformation(DWORD u, BYTE d, void* b) {
        if (!g_OriginalDll && !LoadOriginal()) return ERROR_DEVICE_NOT_CONNECTED;
        return pXInputGetBattery(u, d, b);
    }

    DWORD WINAPI XInputGetKeystroke(DWORD u, DWORD r, void* k) {
        if (!g_OriginalDll && !LoadOriginal()) return ERROR_DEVICE_NOT_CONNECTED;
        return pXInputGetKeystroke(u, r, k);
    }

    DWORD WINAPI Noname100() {
        if (!g_OriginalDll && !LoadOriginal()) return ERROR_DEVICE_NOT_CONNECTED;
        return pUnnamed100();
    }

    DWORD WINAPI Noname101() {
        if (!g_OriginalDll && !LoadOriginal()) return ERROR_DEVICE_NOT_CONNECTED;
        return pUnnamed101();
    }

    DWORD WINAPI Noname102() {
        if (!g_OriginalDll && !LoadOriginal()) return ERROR_DEVICE_NOT_CONNECTED;
        return pUnnamed102();
    }

    DWORD WINAPI Noname103() {
        if (!g_OriginalDll && !LoadOriginal()) return ERROR_DEVICE_NOT_CONNECTED;
        return pUnnamed103();
    }

} // extern "C"

// -----------------------------------------------------------------------------
// DLL entry point
// -----------------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hMod);
        if (!LoadOriginal()) return FALSE;
        // always launch monitor thread
        {
            HANDLE h = CreateThread(nullptr, 0, MonitorThread, nullptr, 0, nullptr);
            if (h) CloseHandle(h);
        }
        break;

    case DLL_PROCESS_DETACH:
        FreeOriginal();
        break;
    }
    return TRUE;
}
