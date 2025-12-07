#include "pluginmain.h"

// -----------------------------------------------------------------
// 环境自检
// -----------------------------------------------------------------
#ifndef _WIN64
#error "严重错误：必须在 Visual Studio 顶部将解决方案平台设置为 x64！"
#endif

#include <windows.h>
#include <commctrl.h> 
#include <string>
#include <vector>
#include <map>
#include <set>
#include <stdio.h>

#pragma comment(lib, "Comctl32.lib") 

#define PLUGIN_NAME "APILogger_Pro"
#define PLUGIN_VERSION 8
#define INI_FILENAME "APILogger.ini"

// -----------------------------------------------------------------
// 全局变量
// -----------------------------------------------------------------
int g_pluginHandle;
int g_hMenu;
HINSTANCE g_hInstance;

const std::vector<std::string> PRESET_APIS = {
    "MessageBoxA", "MessageBoxW", "CreateFileA", "CreateFileW",
    "ReadFile", "WriteFile", "LoadLibraryA", "LoadLibraryW"
};

struct HookInfo { std::string apiName; duint entryAddr; };
struct CallContext { std::string apiName; duint retAddr; };

std::map<duint, HookInfo> g_EntryHooks;
std::map<DWORD, std::vector<CallContext>> g_ThreadCallStacks;
std::set<duint> g_ActiveRetBreakpoints;

// -----------------------------------------------------------------
// 工具函数
// -----------------------------------------------------------------
void Log(const char* format, ...) {
    char buffer[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    _plugin_logprint(buffer);
}

// 智能参数解析
std::string SmartReadParam(duint ptr) {
    if (ptr == 0) return "NULL";
    // 如果 SDK 内部引用失效，这里做个双重保险
    if (!DbgMemIsValidReadPtr(ptr)) {
        char buf[32]; snprintf(buf, 32, "0x%llX", ptr); return std::string(buf);
    }
    unsigned char buffer[64] = { 0 };
    if (DbgMemRead(ptr, buffer, 64)) {
        // Unicode check
        int zeroCount = 0; for (int i = 1; i < 60; i += 2) if (buffer[i] == 0) zeroCount++;
        if (zeroCount > 10 && buffer[0] != 0) {
            std::string res = "L\"";
            for (int i = 0; i < 60; i += 2) {
                char c = buffer[i]; if (c == 0) break;
                res += (c >= 32 && c <= 126) ? c : '.';
            }
            return res + "\"";
        }
        // ANSI check
        bool ansi = true; int len = 0;
        for (; len < 60; len++) { if (buffer[len] == 0) break; if (buffer[len] < 32 || buffer[len]>126) { ansi = false; break; } }
        if (ansi && len > 1) return "A\"" + std::string((char*)buffer) + "\"";
    }
    char buf[32]; snprintf(buf, 32, "0x%llX", ptr); return std::string(buf);
}

// -----------------------------------------------------------------
// 回调函数
// -----------------------------------------------------------------
void OnBreakpoint(CBTYPE cbType, void* callbackInfo) {
    PLUG_CB_BREAKPOINT* info = (PLUG_CB_BREAKPOINT*)callbackInfo;
    duint addr = info->breakpoint->addr;

    // 【修复点】改回使用 DbgGetThreadId，因为 pluginmain.h 已经修复了引用
    DWORD tid = DbgGetThreadId();

    if (g_EntryHooks.count(addr)) {
        HookInfo& api = g_EntryHooks[addr];

        // 使用 Script::Register (你有这个文件)
        duint rcx = Script::Register::Get(Script::Register::RCX);
        duint rdx = Script::Register::Get(Script::Register::RDX);
        duint r8 = Script::Register::Get(Script::Register::R8);
        duint sp = Script::Register::Get(Script::Register::RSP);

        Log("[TID:%d] CALL %s( %s, %s, %s )\n", tid, api.apiName.c_str(),
            SmartReadParam(rcx).c_str(), SmartReadParam(rdx).c_str(), SmartReadParam(r8).c_str());

        duint retAddr = 0;
        DbgMemRead(sp, &retAddr, sizeof(duint));

        if (retAddr) {
            CallContext ctx; ctx.apiName = api.apiName; ctx.retAddr = retAddr;
            g_ThreadCallStacks[tid].push_back(ctx);

            if (g_ActiveRetBreakpoints.find(retAddr) == g_ActiveRetBreakpoints.end()) {
                Script::Debug::SetBreakpoint(retAddr);
                g_ActiveRetBreakpoints.insert(retAddr);
            }
        }
        DbgCmdExec("run");
    }
    else if (g_ActiveRetBreakpoints.count(addr)) {
        if (g_ThreadCallStacks.count(tid) && !g_ThreadCallStacks[tid].empty()) {
            CallContext& ctx = g_ThreadCallStacks[tid].back();
            if (addr == ctx.retAddr) {
                duint rax = Script::Register::Get(Script::Register::RAX);
                Log("[TID:%d] RET  %s -> %s\n", tid, ctx.apiName.c_str(), SmartReadParam(rax).c_str());
                g_ThreadCallStacks[tid].pop_back();
            }
        }
        DbgCmdExec("run");
    }
}

void UpdateHooks(const std::set<std::string>& targetApis) {
    for (auto& pair : g_EntryHooks) Script::Debug::DeleteBreakpoint(pair.first);
    g_EntryHooks.clear();
    for (const auto& name : targetApis) {
        duint addr = DbgValFromString(name.c_str());
        if (addr > 0) {
            g_EntryHooks[addr] = { name, addr };
            Script::Debug::SetBreakpoint(addr);
        }
    }
    _plugin_logputs("Hooks Updated!");
}

// -----------------------------------------------------------------
// GUI 部分
// -----------------------------------------------------------------
HWND hListView;
void InitListView(HWND hwnd) {
    hListView = CreateWindowEx(0, WC_LISTVIEW, "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_NOCOLUMNHEADER,
        10, 10, 260, 300, hwnd, (HMENU)101, g_hInstance, NULL);
    ListView_SetExtendedListViewStyle(hListView, LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT);
    LVCOLUMN lvc = { 0 }; lvc.mask = LVCF_WIDTH | LVCF_TEXT; lvc.cx = 240; lvc.pszText = (LPSTR)"API Name";
    SendMessage(hListView, LVM_INSERTCOLUMN, 0, (LPARAM)&lvc);
    for (int i = 0; i < (int)PRESET_APIS.size(); i++) {
        LVITEM lvi = { 0 }; lvi.mask = LVIF_TEXT; lvi.iItem = i; lvi.pszText = (LPSTR)PRESET_APIS[i].c_str();
        SendMessage(hListView, LVM_INSERTITEM, 0, (LPARAM)&lvi);
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_CREATE) {
        InitListView(hwnd);
        CreateWindow("BUTTON", "Apply", WS_CHILD | WS_VISIBLE, 10, 320, 260, 30, hwnd, (HMENU)102, g_hInstance, NULL);
    }
    else if (uMsg == WM_COMMAND && LOWORD(wParam) == 102) {
        std::set<std::string> apis;
        for (int i = 0; i < ListView_GetItemCount(hListView); i++) {
            if (ListView_GetCheckState(hListView, i)) {
                char buf[256]; ListView_GetItemText(hListView, i, 0, buf, 256); apis.insert(buf);
            }
        }
        UpdateHooks(apis); DestroyWindow(hwnd);
    }
    else if (uMsg == WM_CLOSE) DestroyWindow(hwnd);
    else return DefWindowProc(hwnd, uMsg, wParam, lParam);
    return 0;
}

void ShowConfigWindow() {
    WNDCLASS wc = { 0 }; wc.lpfnWndProc = WindowProc; wc.hInstance = g_hInstance;
    wc.lpszClassName = "APICFG"; wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClass(&wc);
    ShowWindow(CreateWindowEx(0, wc.lpszClassName, "Config", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, 0, 300, 400, NULL, NULL, g_hInstance, NULL), SW_SHOW);
}

// -----------------------------------------------------------------
// 插件导出函数
// -----------------------------------------------------------------
extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct) {
    g_hMenu = setupStruct->hMenu;
    _plugin_menuaddentry(g_hMenu, 0, "Settings");
    _plugin_menuaddentry(g_hMenu, 1, "Clear");
    _plugin_registercallback(g_pluginHandle, CB_BREAKPOINT, (CBPLUGIN)OnBreakpoint);
    _plugin_registercallback(g_pluginHandle, CB_MENUENTRY, [](CBTYPE t, void* info) {
        PLUG_CB_MENUENTRY* data = (PLUG_CB_MENUENTRY*)info;
        if (data->hEntry == 0) ShowConfigWindow();
        if (data->hEntry == 1) { std::set<std::string> e; UpdateHooks(e); }
    });
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct) {
    g_pluginHandle = initStruct->pluginHandle;
    snprintf(initStruct->pluginName, sizeof(initStruct->pluginName), PLUGIN_NAME);
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) g_hInstance = hModule;
    return TRUE;
}