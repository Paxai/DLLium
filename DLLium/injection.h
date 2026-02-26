#pragma once

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <string>
#include <vector>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef HMODULE(WINAPI* f_LoadLibraryA)(const char* lpLibFileName);
typedef FARPROC(WINAPI* f_GetProcAddress)(HMODULE hModule, const char* lpProcName);
typedef BOOL(WINAPI* f_DLL_ENTRY_POINT)(void* hDll, DWORD dwReason, void* pReserved);
typedef BOOLEAN(WINAPI* f_RtlAddFunctionTable)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);

enum class InjectionStatus : uint32_t {
	Waiting,
	Executing,
	Finished,
	Error
};

struct ShellcodeData {
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
	f_RtlAddFunctionTable pRtlAddFunctionTable;

	uintptr_t pDllBase;
	uintptr_t EntryPoint;
	
	uintptr_t RelocDir;
	uintptr_t ImportDir;
	uintptr_t ExceptionDir;
	uintptr_t ExceptionSize;
	uintptr_t TLSDir;

	InjectionStatus Status;
	uint32_t ErrorCode;
};

namespace Memory {
	DWORD GetPID(const wchar_t* exeName);
	uintptr_t GetModuleBase(DWORD pid, const wchar_t* modName);
	uintptr_t GetProcAddressEx(HANDLE hProc, uintptr_t moduleBase, const char* functionName);
	
	bool InjectDLL(DWORD pid, const char* szDllFile);

	bool InjectLoadLibrary(DWORD pid, const char* szDllFile);
}

__declspec(noinline) void __stdcall UniversalShellcode(ShellcodeData* pData);
__declspec(noinline) void __stdcall UniversalShellcodeEnd();

void RelocateImage(PBYTE buffer, uintptr_t targetBase);
bool ManualMap(HANDLE hProc, const char* szDllFile);
