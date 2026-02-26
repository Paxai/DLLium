#include "injection.h"
#include "resource.h"
#include <vector>
#include <string>
#include <algorithm>
#include <CommCtrl.h>
#include <shobjidl.h>
#include <sstream>
#include <iomanip>
#include <psapi.h>

#pragma comment(lib, "Comctl32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

HINSTANCE hInst;
HWND hWndMain;
HWND hProcessList;
HWND hDllPath;
HWND hStatus;
HWND hFilter;
HWND hRadioManual;
HWND hRadioLoadLib;
HWND hBtnBrowse;
HWND hLogConsole;

std::vector<float> cpuHistory(50, 0.0f);
std::vector<float> ramHistory(50, 0.0f);
HWND hCpuGraph, hRamGraph;
float currentCpu = 0.0f, currentRam = 0.0f;

struct ProcessInfo {
	DWORD pid;
	std::wstring name;
	std::wstring arch; 
};

std::vector<ProcessInfo> g_Processes;

float GetCpuUsage() {
	static FILETIME lastIdleTime, lastKernelTime, lastUserTime;
	FILETIME idleTime, kernelTime, userTime;

	if (!GetSystemTimes(&idleTime, &kernelTime, &userTime)) return 0;

	auto FileTimeToQuad = [](const FILETIME& ft) { return ((((unsigned __int64)ft.dwHighDateTime) << 32) | ft.dwLowDateTime); };

	unsigned __int64 idleDelta = FileTimeToQuad(idleTime) - FileTimeToQuad(lastIdleTime);
	unsigned __int64 kernelDelta = FileTimeToQuad(kernelTime) - FileTimeToQuad(lastKernelTime);
	unsigned __int64 userDelta = FileTimeToQuad(userTime) - FileTimeToQuad(lastUserTime);

	lastIdleTime = idleTime;
	lastKernelTime = kernelTime;
	lastUserTime = userTime;

	unsigned __int64 totalDelta = kernelDelta + userDelta;
	if (totalDelta == 0) return 0;

	return (float)(totalDelta - idleDelta) * 100.0f / totalDelta;
}

float GetRamUsageInMB() {
	MEMORYSTATUSEX memInfo;
	memInfo.dwLength = sizeof(MEMORYSTATUSEX);
	GlobalMemoryStatusEx(&memInfo);
	return (float)((memInfo.ullTotalPhys - memInfo.ullAvailPhys) / (1024 * 1024));
}

void DrawGraph(HDC hdc, const std::vector<float>& history, const std::wstring& label, float maxVal, COLORREF color, const RECT& rc) {
	HDC memDC = CreateCompatibleDC(hdc);
	HBITMAP memBM = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
	SelectObject(memDC, memBM);

	HBRUSH hBack = CreateSolidBrush(RGB(30, 30, 30));
	FillRect(memDC, &rc, hBack);
	DeleteObject(hBack);

	HPEN hGridPen = CreatePen(PS_SOLID, 1, RGB(45, 45, 45));
	SelectObject(memDC, hGridPen);
	for (int i = 0; i < rc.bottom; i += 20) { MoveToEx(memDC, 0, i, NULL); LineTo(memDC, rc.right, i); }
	for (int i = 0; i < rc.right; i += 20) { MoveToEx(memDC, i, 0, NULL); LineTo(memDC, i, rc.bottom); }
	DeleteObject(hGridPen);

	if (!history.empty() && maxVal > 0) {
		HPEN hLinePen = CreatePen(PS_SOLID, 2, color);
		SelectObject(memDC, hLinePen);

		float step = (float)rc.right / (history.size() - 1);
		
		std::vector<POINT> pts;
		pts.push_back({ 0, rc.bottom });

		for (size_t i = 0; i < history.size(); i++) {
			float val = (history[i] / maxVal) * (rc.bottom - 10);
			if (val > rc.bottom - 5) val = (float)rc.bottom - 5;
			int x = (int)(i * step);
			int y = rc.bottom - (int)val;
			pts.push_back({ x, y });
		}
		pts.push_back({ rc.right, rc.bottom });

		SelectObject(memDC, GetStockObject(NULL_PEN));
		HBRUSH hAlphaBrush = CreateHatchBrush(HS_BDIAGONAL, RGB(GetRValue(color)/3, GetGValue(color)/3, GetBValue(color)/3));
		SelectObject(memDC, hAlphaBrush);
		Polygon(memDC, pts.data(), (int)pts.size());
		DeleteObject(hAlphaBrush);

		SelectObject(memDC, hLinePen);
		for (size_t i = 1; i < pts.size() - 1; i++) {
			if (i == 1) MoveToEx(memDC, pts[i].x, pts[i].y, NULL);
			else LineTo(memDC, pts[i].x, pts[i].y);
		}
		DeleteObject(hLinePen);
	}

	SetTextColor(memDC, RGB(220, 220, 220));
	SetBkMode(memDC, TRANSPARENT);
	HFONT hSmallFont = CreateFontW(12, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
	SelectObject(memDC, hSmallFont);
	
	wchar_t fullLabel[64];
	float lastVal = history.empty() ? 0 : history.back();
	if (maxVal == 100.0f) swprintf_s(fullLabel, L"%s: %.1f%%", label.c_str(), lastVal);
	else swprintf_s(fullLabel, L"%s: %.0f MB", label.c_str(), lastVal);
	
	TextOutW(memDC, 5, 2, fullLabel, (int)wcslen(fullLabel));
	DeleteObject(hSmallFont);

	BitBlt(hdc, 0, 0, rc.right, rc.bottom, memDC, 0, 0, SRCCOPY);

	DeleteDC(memDC);
	DeleteObject(memBM);
}




bool IsProcess64(DWORD pid) {
	HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!hProc) return false;

	BOOL bIsWow64 = FALSE;
	IsWow64Process(hProc, &bIsWow64);
	CloseHandle(hProc);

	if (bIsWow64) return false;

	SYSTEM_INFO si;
	GetNativeSystemInfo(&si);
	return (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
}














void PopulateListView(const std::wstring& filter = L"") {
	ListView_DeleteAllItems(hProcessList);

	int itemIdx = 0;
	for (int i = 0; i < (int)g_Processes.size(); i++) {
		const auto& p = g_Processes[i];
		if (!filter.empty()) {
			std::wstring lName = p.name;
			std::wstring lFilter = filter;
			std::transform(lName.begin(), lName.end(), lName.begin(), ::towlower);
			std::transform(lFilter.begin(), lFilter.end(), lFilter.begin(), ::towlower);
			if (lName.find(lFilter) == std::wstring::npos) continue;
		}

		LVITEMW lvItem = { 0 };
		lvItem.mask = LVIF_TEXT | LVIF_PARAM;
		lvItem.iItem = itemIdx;
		lvItem.iSubItem = 0;
		lvItem.pszText = const_cast<LPWSTR>(p.name.c_str());
		lvItem.lParam = (LPARAM)i;
		ListView_InsertItem(hProcessList, &lvItem);

		std::wstring pidStr = std::to_wstring(p.pid);
		ListView_SetItemText(hProcessList, itemIdx, 1, const_cast<LPWSTR>(pidStr.c_str()));
		ListView_SetItemText(hProcessList, itemIdx, 2, const_cast<LPWSTR>(p.arch.c_str()));

		itemIdx++;
	}
}

void RefreshProcessList() {
	g_Processes.clear();

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) return;

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (Process32FirstW(hSnap, &pe32)) {
		do {
			ProcessInfo info;
			info.pid = pe32.th32ProcessID;
			info.name = pe32.szExeFile;
			info.arch = IsProcess64(info.pid) ? L"x64" : L"x86";
			g_Processes.push_back(info);
		} while (Process32NextW(hSnap, &pe32));
	}
	CloseHandle(hSnap);

	std::sort(g_Processes.begin(), g_Processes.end(), [](const ProcessInfo& a, const ProcessInfo& b) {
		std::wstring an = a.name, bn = b.name;
		std::transform(an.begin(), an.end(), an.begin(), ::towlower);
		std::transform(bn.begin(), bn.end(), bn.begin(), ::towlower);
		return an < bn;
	});

	wchar_t filterBuf[256] = {};
	if (hFilter) GetWindowTextW(hFilter, filterBuf, 256);
	PopulateListView(filterBuf);

	SetWindowTextW(hStatus, L"Ready");
}

void Log(const std::wstring& message) {
	if (hLogConsole == NULL) return;
	
	SYSTEMTIME st;
	GetLocalTime(&st);
	wchar_t timeBuf[32];
	swprintf_s(timeBuf, L"[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
	
	std::wstring entry = timeBuf + message + L"\r\n";
	
	int len = GetWindowTextLengthW(hLogConsole);
	SendMessageW(hLogConsole, EM_SETSEL, len, len);
	SendMessageW(hLogConsole, EM_REPLACESEL, FALSE, (LPARAM)entry.c_str());
	SendMessageW(hLogConsole, WM_VSCROLL, SB_BOTTOM, 0);
}

void BrowseDll() {
	IFileOpenDialog* pFileOpen;
	HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_ALL, IID_IFileOpenDialog, reinterpret_cast<void**>(&pFileOpen));

	if (SUCCEEDED(hr)) {
		COMDLG_FILTERSPEC rgSpec[] = { { L"DLL Files", L"*.dll" }, { L"All Files", L"*.*" } };
		pFileOpen->SetFileTypes(2, rgSpec);
		hr = pFileOpen->Show(NULL);

		if (SUCCEEDED(hr)) {
			IShellItem* pItem;
			hr = pFileOpen->GetResult(&pItem);
			if (SUCCEEDED(hr)) {
				PWSTR pszFilePath;
				hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
				if (SUCCEEDED(hr)) {
					SetWindowTextW(hDllPath, pszFilePath);
					CoTaskMemFree(pszFilePath);
				}
				pItem->Release();
			}
		}
		pFileOpen->Release();
	}
}

struct InjectParams {
	DWORD pid;
	std::wstring procName;
	char szDllPathA[MAX_PATH];
	bool useManualMap;
};

DWORD WINAPI InjectThread(LPVOID lpParam) {
	InjectParams* p = (InjectParams*)lpParam;

	bool success = false;
	if (p->useManualMap) {
		success = Memory::InjectDLL(p->pid, p->szDllPathA);
	}
	else {
		success = Memory::InjectLoadLibrary(p->pid, p->szDllPathA);
	}

	if (success) {
		SetWindowTextW(hStatus, L"Success!");
		Log(L"SUCCESS: Module injected successfully!");
	}
	else {
		SetWindowTextW(hStatus, L"Failed.");
		Log(L"ERROR: Injection failed! Check: admin rights, DLL architecture (x64/x86), DLL integrity.");
	}

	EnableWindow(GetDlgItem(hWndMain, 2), TRUE);

	delete p;
	return 0;
}

void Inject() {
	int sel = ListView_GetNextItem(hProcessList, -1, LVNI_SELECTED);
	if (sel == -1) {
		Log(L"Error: Select a process from the list.");
		return;
	}

	wchar_t szDllPathW[MAX_PATH];
	GetWindowTextW(hDllPath, szDllPathW, MAX_PATH);
	if (wcslen(szDllPathW) == 0) {
		Log(L"Error: Select a DLL file.");
		return;
	}

	if (GetFileAttributesW(szDllPathW) == INVALID_FILE_ATTRIBUTES) {
		Log(L"Error: DLL file does not exist or access denied.");
		return;
	}

	LVITEMW lvItem = { 0 };
	lvItem.mask = LVIF_PARAM;
	lvItem.iItem = sel;
	ListView_GetItem(hProcessList, &lvItem);
	int dataIdx = (int)lvItem.lParam;

	if (dataIdx < 0 || dataIdx >= (int)g_Processes.size()) {
		Log(L"Error: Invalid process index.");
		return;
	}

	DWORD pid = g_Processes[dataIdx].pid;
	std::wstring procName = g_Processes[dataIdx].name;

	Log(L"Injecting into: " + procName + L" (PID: " + std::to_wstring(pid) + L")...");

	InjectParams* params = new InjectParams();
	params->pid = pid;
	params->procName = procName;
	params->useManualMap = (SendMessage(hRadioManual, BM_GETCHECK, 0, 0) == BST_CHECKED);

	size_t convertedChars = 0;
	wcstombs_s(&convertedChars, params->szDllPathA, szDllPathW, MAX_PATH);

	if (params->useManualMap) {
		Log(L"Mode: Manual Map...");
	}
	else {
		Log(L"Mode: LoadLibrary...");
	}

	EnableWindow(GetDlgItem(hWndMain, 2), FALSE);
	SetWindowTextW(hStatus, L"Injecting...");

	HANDLE hThread = CreateThread(nullptr, 0, InjectThread, params, 0, nullptr);
	if (hThread) {
		CloseHandle(hThread);
	}
	else {
		delete params;
		EnableWindow(GetDlgItem(hWndMain, 2), TRUE);
		Log(L"Error: Failed to create thread.");
	}
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
	switch (message) {
	case WM_CREATE: {
		HFONT hFont = CreateFontW(16, 0, 0, 0, FW_REGULAR, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
		HFONT hConsoleFont = CreateFontW(14, 0, 0, 0, FW_REGULAR, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");

		HWND hLabelDLL = CreateWindowW(L"STATIC", L"DLL Settings:", WS_VISIBLE | WS_CHILD, 20, 20, 220, 18, hWnd, NULL, hInst, NULL);
		SendMessage(hLabelDLL, WM_SETFONT, (WPARAM)hFont, TRUE);

		hDllPath = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 20, 45, 175, 25, hWnd, NULL, hInst, NULL);
		SendMessage(hDllPath, WM_SETFONT, (WPARAM)hFont, TRUE);

		hBtnBrowse = CreateWindowW(L"BUTTON", L"...", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 200, 45, 40, 25, hWnd, (HMENU)1, hInst, NULL);
		SendMessage(hBtnBrowse, WM_SETFONT, (WPARAM)hFont, TRUE);

		hRadioManual = CreateWindowW(L"BUTTON", L"Manual Map (Stealth)", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON | WS_GROUP, 20, 80, 220, 20, hWnd, NULL, hInst, NULL);
		SendMessage(hRadioManual, WM_SETFONT, (WPARAM)hFont, TRUE);
		SendMessage(hRadioManual, BM_SETCHECK, BST_CHECKED, 0);

		hRadioLoadLib = CreateWindowW(L"BUTTON", L"LoadLibrary (Normal)", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON, 20, 100, 220, 20, hWnd, NULL, hInst, NULL);
		SendMessage(hRadioLoadLib, WM_SETFONT, (WPARAM)hFont, TRUE);

		HWND hBtnInject = CreateWindowW(L"BUTTON", L"INJECT", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 20, 130, 220, 45, hWnd, (HMENU)2, hInst, NULL);
		SendMessage(hBtnInject, WM_SETFONT, (WPARAM)hFont, TRUE);

		hCpuGraph = CreateWindowW(L"STATIC", L"", WS_VISIBLE | WS_CHILD | SS_OWNERDRAW, 20, 190, 220, 80, hWnd, (HMENU)10, hInst, NULL);
		hRamGraph = CreateWindowW(L"STATIC", L"", WS_VISIBLE | WS_CHILD | SS_OWNERDRAW, 20, 285, 220, 80, hWnd, (HMENU)11, hInst, NULL);

		HFONT hSmallBold = CreateFontW(13, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
		HWND hLabelVersion = CreateWindowW(L"STATIC", L"v1.0", WS_VISIBLE | WS_CHILD | SS_CENTER, 20, 375, 220, 18, hWnd, NULL, hInst, NULL);
		SendMessage(hLabelVersion, WM_SETFONT, (WPARAM)hSmallBold, TRUE);
		HWND hLabelAuthor = CreateWindowW(L"STATIC", L"by GrubyPiez", WS_VISIBLE | WS_CHILD | SS_CENTER, 20, 394, 220, 18, hWnd, NULL, hInst, NULL);
		SendMessage(hLabelAuthor, WM_SETFONT, (WPARAM)hSmallBold, TRUE);

		HWND hLabelProc = CreateWindowW(L"STATIC", L"Processes:", WS_VISIBLE | WS_CHILD, 260, 20, 120, 18, hWnd, NULL, hInst, NULL);
		SendMessage(hLabelProc, WM_SETFONT, (WPARAM)hFont, TRUE);

		hFilter = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 380, 18, 160, 22, hWnd, (HMENU)4, hInst, NULL);
		SendMessage(hFilter, WM_SETFONT, (WPARAM)hFont, TRUE);
		SendMessage(hFilter, EM_SETCUEBANNER, TRUE, (LPARAM)L"Search...");

		HWND hBtnRefresh = CreateWindowW(L"BUTTON", L"Refresh", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 550, 18, 70, 22, hWnd, (HMENU)3, hInst, NULL);
		SendMessage(hBtnRefresh, WM_SETFONT, (WPARAM)hFont, TRUE);

		hProcessList = CreateWindowW(WC_LISTVIEWW, L"", WS_VISIBLE | WS_CHILD | WS_BORDER | LVS_REPORT | LVS_SINGLESEL | WS_VSCROLL, 260, 45, 360, 430, hWnd, NULL, hInst, NULL);
		SendMessage(hProcessList, WM_SETFONT, (WPARAM)hFont, TRUE);
		ListView_SetExtendedListViewStyle(hProcessList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

		LVCOLUMNW lvc = { 0 };
		lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
		lvc.pszText = (LPWSTR)L"Name";
		lvc.cx = 180;
		ListView_InsertColumn(hProcessList, 0, &lvc);

		lvc.pszText = (LPWSTR)L"PID";
		lvc.cx = 80;
		ListView_InsertColumn(hProcessList, 1, &lvc);

		lvc.pszText = (LPWSTR)L"Arch";
		lvc.cx = 70;
		ListView_InsertColumn(hProcessList, 2, &lvc);

		HWND hLabelConsole = CreateWindowW(L"STATIC", L"Console Log:", WS_VISIBLE | WS_CHILD, 640, 20, 340, 18, hWnd, NULL, hInst, NULL);
		SendMessage(hLabelConsole, WM_SETFONT, (WPARAM)hFont, TRUE);

		hLogConsole = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | ES_READONLY, 640, 45, 330, 430, hWnd, NULL, hInst, NULL);
		SendMessage(hLogConsole, WM_SETFONT, (WPARAM)hConsoleFont, TRUE);

		hStatus = CreateWindowW(L"STATIC", L"Ready", WS_VISIBLE | WS_CHILD | SS_CENTER, 640, 480, 330, 20, hWnd, NULL, hInst, NULL);
		SendMessage(hStatus, WM_SETFONT, (WPARAM)hFont, TRUE);

		SetTimer(hWnd, 1, 500, NULL);
		RefreshProcessList();
		Log(L"DLLium initialized.");
		break;
	}
	case WM_TIMER: {
		if (wParam == 1) {
			cpuHistory.erase(cpuHistory.begin());
			cpuHistory.push_back(GetCpuUsage());
			
			ramHistory.erase(ramHistory.begin());
			ramHistory.push_back(GetRamUsageInMB());

			InvalidateRect(hCpuGraph, NULL, FALSE);
			InvalidateRect(hRamGraph, NULL, FALSE);
		}
		break;
	}
	case WM_DRAWITEM: {
		LPDRAWITEMSTRUCT lpDrawItem = (LPDRAWITEMSTRUCT)lParam;
		if (lpDrawItem->CtlID == 10) {
			DrawGraph(lpDrawItem->hDC, cpuHistory, L"CPU", 100.0f, RGB(0, 160, 240), lpDrawItem->rcItem);
		}
		else if (lpDrawItem->CtlID == 11) {
			MEMORYSTATUSEX memInfo;
			memInfo.dwLength = sizeof(MEMORYSTATUSEX);
			GlobalMemoryStatusEx(&memInfo);
			DrawGraph(lpDrawItem->hDC, ramHistory, L"RAM", (float)(memInfo.ullTotalPhys / (1024 * 1024)), RGB(0, 200, 100), lpDrawItem->rcItem);
		}
		return TRUE;
	}
	case WM_COMMAND: {
		int wmId = LOWORD(wParam);
		int notif = HIWORD(wParam);
		switch (wmId) {
		case 1: BrowseDll(); break;
		case 2: Inject(); break;
		case 3: RefreshProcessList(); break;
		case 4:
			if (notif == EN_CHANGE) {
				wchar_t filterBuf[256] = {};
				GetWindowTextW(hFilter, filterBuf, 256);
				PopulateListView(filterBuf);
			}
			break;
		}
		break;
	}
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default: return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nCmdShow) {
	hInst = hInstance;
	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_LISTVIEW_CLASSES };
	InitCommonControlsEx(&icex);

	WNDCLASSEXW wcex = { sizeof(WNDCLASSEX) };
	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = WndProc;
	wcex.hInstance = hInstance;
	wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_DLLIUM));
	wcex.hIconSm = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_DLLIUM));
	wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
	wcex.lpszClassName = L"DLLiumGUI";

	RegisterClassExW(&wcex);

	hWndMain = CreateWindowW(L"DLLiumGUI", L"DLLium", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 1000, 560, NULL, NULL, hInstance, NULL);

	if (!hWndMain) return FALSE;

	ShowWindow(hWndMain, nCmdShow);
	UpdateWindow(hWndMain);

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	CoUninitialize();
	return (int)msg.wParam;
}
