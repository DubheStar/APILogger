#pragma once

// 1. 强制定义 x64 环境
#ifndef _WIN64
#define _WIN64
#endif

#include <windows.h>

// 2. 【关键】手动按依赖顺序引用 SDK 文件
// 这样可以绕过扁平化目录导致的 "include" 路径错误
#include "_plugin_types.h"
#include "_plugins.h"           // 修复 PLUG_SETUPSTRUCT 报错
#include "_dbgfunctions.h"      // 修复 DbgGetThreadId 报错

// 3. 引用 Script 相关 (你有这些文件)
#include "_scriptapi_argument.h"
#include "_scriptapi_assembler.h"
#include "_scriptapi_debug.h" 
#include "_scriptapi_memory.h"
#include "_scriptapi_register.h" // 修复 Script::Register
#include "_scriptapi_gui.h"

// 4. 最后引用 Bridge
#include "bridgemain.h"

// 5. 导出定义
#ifndef DLL_EXPORT
#define DLL_EXPORT __declspec(dllexport)
#endif