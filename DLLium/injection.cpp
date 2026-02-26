#include "injection.h"

__declspec(noinline) void __stdcall UniversalShellcode(ShellcodeData* pData) {
	if (!pData || !pData->pDllBase) {
		if (pData) pData->Status = InjectionStatus::Error;
		return;
	}

	pData->Status = InjectionStatus::Executing;

	uintptr_t pBase = pData->pDllBase;

	if (pData->ImportDir) {
		auto* pImportDescr = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pBase + pData->ImportDir);
		while (pImportDescr->Name) {
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HMODULE hMod = pData->pLoadLibraryA(szMod);
			if (!hMod) {
				pData->Status = InjectionStatus::Error;
				pData->ErrorCode = 1;
				return;
			}

			auto* pIAT = reinterpret_cast<PIMAGE_THUNK_DATA>(pBase + pImportDescr->FirstThunk);

			PIMAGE_THUNK_DATA pThunk = pIAT;
			if (pImportDescr->OriginalFirstThunk) {
				pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(pBase + pImportDescr->OriginalFirstThunk);
			}

			while (pThunk->u1.AddressOfData) {
				if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {
					pIAT->u1.Function = (uintptr_t)pData->pGetProcAddress(hMod, (LPCSTR)(pThunk->u1.Ordinal & 0xFFFF));
				}
				else {
					auto* pImportByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + pThunk->u1.AddressOfData);
					pIAT->u1.Function = (uintptr_t)pData->pGetProcAddress(hMod, pImportByName->Name);
				}
				pThunk++;
				pIAT++;
			}
			pImportDescr++;
		}
	}

	if (pData->TLSDir) {
		auto* pTLS = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(pBase + pData->TLSDir);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		if (pCallback) {
			while (*pCallback) {
				(*pCallback)(reinterpret_cast<void*>(pBase), DLL_PROCESS_ATTACH, nullptr);
				pCallback++;
			}
		}
	}

	if (pData->pRtlAddFunctionTable && pData->ExceptionDir && pData->ExceptionSize) {
		auto* pFuncTable = reinterpret_cast<PRUNTIME_FUNCTION>(pBase + pData->ExceptionDir);
		DWORD count = (DWORD)(pData->ExceptionSize / sizeof(RUNTIME_FUNCTION));
		pData->pRtlAddFunctionTable(pFuncTable, count, (DWORD64)pBase);
	}

	if (pData->EntryPoint) {
		auto fEntryPoint = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pData->EntryPoint);
		fEntryPoint(reinterpret_cast<void*>(pBase), DLL_PROCESS_ATTACH, nullptr);
	}

	pData->Status = InjectionStatus::Finished;
}

__declspec(noinline) void __stdcall UniversalShellcodeEnd() {
}

static void* ResolveFunction(void* ptr) {
	unsigned char* b = (unsigned char*)ptr;
	if (b[0] == 0xE9) {
		int rel = *(int*)(b + 1);
		return (void*)(b + 5 + rel);
	}
	if (b[0] == 0xFF && b[1] == 0x25) {
		int disp = *(int*)(b + 2);
		void** target = (void**)(b + 6 + disp);
		return *target;
	}
	return ptr;
}

namespace Memory {

	DWORD GetPID(const wchar_t* exeName) {
		DWORD pid = 0;
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32W pe32;
			pe32.dwSize = sizeof(pe32);
			if (Process32FirstW(hSnap, &pe32)) {
				do {
					if (!wcscmp(pe32.szExeFile, exeName)) {
						pid = pe32.th32ProcessID;
						break;
					}
				} while (Process32NextW(hSnap, &pe32));
			}
			CloseHandle(hSnap);
		}
		return pid;
	}

	uintptr_t GetModuleBase(DWORD pid, const wchar_t* modName) {
		uintptr_t base = 0;
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
		if (hSnap != INVALID_HANDLE_VALUE) {
			MODULEENTRY32W me32;
			me32.dwSize = sizeof(me32);
			if (Module32FirstW(hSnap, &me32)) {
				do {
					if (!_wcsicmp(me32.szModule, modName)) {
						base = (uintptr_t)me32.modBaseAddr;
						break;
					}
				} while (Module32NextW(hSnap, &me32));
			}
			CloseHandle(hSnap);
		}
		return base;
	}

	uintptr_t GetProcAddressEx(HANDLE hProc, uintptr_t moduleBase, const char* functionName) {
		if (!moduleBase) return 0;
		IMAGE_DOS_HEADER dos;
		if (!ReadProcessMemory(hProc, (LPCVOID)moduleBase, &dos, sizeof(dos), nullptr)) return 0;
		IMAGE_NT_HEADERS nt;
		if (!ReadProcessMemory(hProc, (LPCVOID)(moduleBase + dos.e_lfanew), &nt, sizeof(nt), nullptr)) return 0;

		auto exportDirRva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (!exportDirRva) return 0;

		IMAGE_EXPORT_DIRECTORY exports;
		if (!ReadProcessMemory(hProc, (LPCVOID)(moduleBase + exportDirRva), &exports, sizeof(exports), nullptr)) return 0;

		std::vector<DWORD> functionRVAs(exports.NumberOfFunctions);
		ReadProcessMemory(hProc, (LPCVOID)(moduleBase + exports.AddressOfFunctions), functionRVAs.data(), exports.NumberOfFunctions * sizeof(DWORD), nullptr);

		std::vector<DWORD> nameRVAs(exports.NumberOfNames);
		ReadProcessMemory(hProc, (LPCVOID)(moduleBase + exports.AddressOfNames), nameRVAs.data(), exports.NumberOfNames * sizeof(DWORD), nullptr);

		std::vector<WORD> ordinals(exports.NumberOfNames);
		ReadProcessMemory(hProc, (LPCVOID)(moduleBase + exports.AddressOfNameOrdinals), ordinals.data(), exports.NumberOfNames * sizeof(WORD), nullptr);

		for (size_t i = 0; i < nameRVAs.size(); ++i) {
			char name[256] = {};
			if (ReadProcessMemory(hProc, (LPCVOID)(moduleBase + nameRVAs[i]), name, 255, nullptr)) {
				if (!strcmp(name, functionName)) {
					return moduleBase + functionRVAs[ordinals[i]];
				}
			}
		}
		return 0;
	}

	bool InjectDLL(DWORD pid, const char* szDllFile) {
		std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);
		if (File.fail()) return false;

		std::streampos fileSize = File.tellg();
		if (fileSize < 0x1000) { File.close(); return false; }

		std::vector<BYTE> pSrcData((size_t)fileSize);
		File.seekg(0, std::ios::beg);
		File.read((char*)pSrcData.data(), fileSize);
		File.close();

		auto* pDosLocal = reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData.data());
		if (pDosLocal->e_magic != IMAGE_DOS_SIGNATURE) return false;

		auto* pNtLocal = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData.data() + pDosLocal->e_lfanew);
		if (pNtLocal->Signature != IMAGE_NT_SIGNATURE) return false;
		auto* pOpt = &pNtLocal->OptionalHeader;

		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (!hProc) return false;

		LPVOID pTargetBase = VirtualAllocEx(hProc, nullptr, pOpt->SizeOfImage,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pTargetBase) {
			CloseHandle(hProc);
			return false;
		}

		BYTE* pLocalImage = (BYTE*)VirtualAlloc(nullptr, pOpt->SizeOfImage,
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!pLocalImage) {
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			CloseHandle(hProc);
			return false;
		}

		memcpy(pLocalImage, pSrcData.data(), pOpt->SizeOfHeaders);

		auto* pSection = IMAGE_FIRST_SECTION(pNtLocal);
		for (UINT i = 0; i < pNtLocal->FileHeader.NumberOfSections; ++i, ++pSection) {
			if (pSection->SizeOfRawData > 0) {
				memcpy(pLocalImage + pSection->VirtualAddress,
					pSrcData.data() + pSection->PointerToRawData,
					pSection->SizeOfRawData);
			}
		}

		RelocateImage(pLocalImage, (uintptr_t)pTargetBase);

		if (!WriteProcessMemory(hProc, pTargetBase, pLocalImage, pOpt->SizeOfImage, nullptr)) {
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFree(pLocalImage, 0, MEM_RELEASE);
			CloseHandle(hProc);
			return false;
		}
		VirtualFree(pLocalImage, 0, MEM_RELEASE);
		pLocalImage = nullptr;

		HMODULE hK32Local = GetModuleHandleA("kernel32.dll");
		if (!hK32Local) {
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			CloseHandle(hProc);
			return false;
		}

		auto pRtlAddFuncTableLocal = (f_RtlAddFunctionTable)GetProcAddress(hK32Local, "RtlAddFunctionTable");
		auto pLoadLibraryALocal    = (f_LoadLibraryA)GetProcAddress(hK32Local, "LoadLibraryA");
		auto pGetProcAddressLocal  = (f_GetProcAddress)GetProcAddress(hK32Local, "GetProcAddress");

		if (!pLoadLibraryALocal || !pGetProcAddressLocal) {
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			CloseHandle(hProc);
			return false;
		}

		ShellcodeData data = {};
		data.pDllBase             = (uintptr_t)pTargetBase;
		data.EntryPoint           = pOpt->AddressOfEntryPoint;
		data.ImportDir            = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		data.RelocDir             = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		data.ExceptionDir         = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
		data.ExceptionSize        = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
		data.TLSDir               = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
		data.Status               = InjectionStatus::Waiting;
		data.ErrorCode            = 0;
		data.pLoadLibraryA        = pLoadLibraryALocal;
		data.pGetProcAddress      = pGetProcAddressLocal;
		data.pRtlAddFunctionTable = pRtlAddFuncTableLocal;

		LPVOID pRemoteData = VirtualAllocEx(hProc, nullptr, sizeof(ShellcodeData),
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!pRemoteData) {
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			CloseHandle(hProc);
			return false;
		}
		WriteProcessMemory(hProc, pRemoteData, &data, sizeof(ShellcodeData), nullptr);

		void* scStart = ResolveFunction((void*)UniversalShellcode);
		void* scEnd   = ResolveFunction((void*)UniversalShellcodeEnd);
		size_t shellcodeSize = (uintptr_t)scEnd - (uintptr_t)scStart;

		if (shellcodeSize == 0 || shellcodeSize > 0x8000) {
			shellcodeSize = 0x1000;
		}

		LPVOID pRemoteShellcode = VirtualAllocEx(hProc, nullptr, shellcodeSize,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pRemoteShellcode) {
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pRemoteData, 0, MEM_RELEASE);
			CloseHandle(hProc);
			return false;
		}
		WriteProcessMemory(hProc, pRemoteShellcode, scStart, shellcodeSize, nullptr);

		HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
			(LPTHREAD_START_ROUTINE)pRemoteShellcode, pRemoteData, 0, nullptr);
		if (!hThread) {
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pRemoteData, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pRemoteShellcode, 0, MEM_RELEASE);
			CloseHandle(hProc);
			return false;
		}

		InjectionStatus status = InjectionStatus::Waiting;
		for (int i = 0; i < 1000; i++) {
			ReadProcessMemory(hProc,
				(LPCVOID)((uintptr_t)pRemoteData + offsetof(ShellcodeData, Status)),
				&status, sizeof(status), nullptr);
			if (status == InjectionStatus::Finished || status == InjectionStatus::Error) break;

			DWORD exitCode = STILL_ACTIVE;
			GetExitCodeThread(hThread, &exitCode);
			if (exitCode != STILL_ACTIVE) break;

			Sleep(10);
		}

		CloseHandle(hThread);
		VirtualFreeEx(hProc, pRemoteData, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pRemoteShellcode, 0, MEM_RELEASE);
		CloseHandle(hProc);

		return (status == InjectionStatus::Finished);
	}

	bool InjectLoadLibrary(DWORD pid, const char* szDllFile) {
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (!hProc) return false;

		size_t pathLen = strlen(szDllFile) + 1;
		LPVOID pRemotePath = VirtualAllocEx(hProc, nullptr, pathLen,
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!pRemotePath) {
			CloseHandle(hProc);
			return false;
		}

		if (!WriteProcessMemory(hProc, pRemotePath, szDllFile, pathLen, nullptr)) {
			VirtualFreeEx(hProc, pRemotePath, 0, MEM_RELEASE);
			CloseHandle(hProc);
			return false;
		}

		FARPROC pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		if (!pLoadLibrary) {
			VirtualFreeEx(hProc, pRemotePath, 0, MEM_RELEASE);
			CloseHandle(hProc);
			return false;
		}

		HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
			(LPTHREAD_START_ROUTINE)pLoadLibrary, pRemotePath, 0, nullptr);
		if (!hThread) {
			VirtualFreeEx(hProc, pRemotePath, 0, MEM_RELEASE);
			CloseHandle(hProc);
			return false;
		}

		WaitForSingleObject(hThread, INFINITE);

		DWORD hModResult = 0;
		GetExitCodeThread(hThread, &hModResult);
		bool success = (hModResult != 0);

		VirtualFreeEx(hProc, pRemotePath, 0, MEM_RELEASE);
		CloseHandle(hThread);
		CloseHandle(hProc);
		return success;
	}

}

void RelocateImage(PBYTE buffer, uintptr_t targetBase) {
	auto* pDosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer);
	auto* pNt     = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer + pDosHdr->e_lfanew);
	auto* pOpt    = &pNt->OptionalHeader;

	uintptr_t delta = targetBase - (uintptr_t)pOpt->ImageBase;
	if (delta == 0) return;

	auto relocDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (relocDir.Size == 0) return;

	auto* pReloc    = reinterpret_cast<IMAGE_BASE_RELOCATION*>(buffer + relocDir.VirtualAddress);
	uintptr_t relocEnd = (uintptr_t)pReloc + relocDir.Size;

	while (pReloc && (uintptr_t)pReloc < relocEnd && pReloc->SizeOfBlock > sizeof(IMAGE_BASE_RELOCATION)) {
		UINT  count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		WORD* info  = reinterpret_cast<WORD*>(pReloc + 1);

		for (UINT i = 0; i < count; ++i) {
			WORD type   = info[i] >> 12;
			WORD offset = info[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64) {
				uintptr_t* patch = reinterpret_cast<uintptr_t*>(buffer + pReloc->VirtualAddress + offset);
				*patch += delta;
			}
			else if (type == IMAGE_REL_BASED_HIGHLOW) {
				uint32_t* patch = reinterpret_cast<uint32_t*>(buffer + pReloc->VirtualAddress + offset);
				*patch += (uint32_t)delta;
			}
		}

		pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
			reinterpret_cast<BYTE*>(pReloc) + pReloc->SizeOfBlock);
	}
}
