#pragma GCC optimize(3)
#include <windows.h>
#include <tlhelp32.h>
#include <commctrl.h>
#include<iostream>
using namespace std;
HANDLE thread;
HFONT hFont;
HWND TxOut,TxSum,TxDsb,focus;
bool bWorking =true;
ULONG64 sum=0;
BOOL CALLBACK SetWindowFont(HWND hwndChild, LPARAM lParam) {
	SendMessage(hwndChild, WM_SETFONT, WPARAM(hFont), 0);
	return TRUE;
}
DWORD WINAPI ThreadProc(LPVOID lpParameter) {
	while(true){
		ULONG64 sumTmp = sum;
		PROCESSENTRY32 pe;  // 进程信息
		pe.dwSize = sizeof(PROCESSENTRY32);
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // 获取系统进程列表
		if (Process32First(hSnapshot, &pe)) {   // 返回系统中第一个进程的信息
			do {
				if (0 == _stricmp(pe.szExeFile, "cmd.exe")) { // 不区分大小写比较
					HANDLE h=OpenProcess(PROCESS_TERMINATE,FALSE,pe.th32ProcessID);
					TerminateProcess(h,0);
					CloseHandle(h);
					sum++;
				}
			} while (Process32Next(hSnapshot, &pe));     // 下一个进程
		}
		CloseHandle(hSnapshot);     // 删除快照
		if(sumTmp != sum){
			char c[BUFSIZ];
			sprintf(c,"已清除%lld个",sum);
			SetWindowText(TxSum,c);
		}
		Sleep(25);
	}
	return 0L;
}

/* This is where all the input to the window goes to */
LRESULT CALLBACK WndProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam) {
	switch(Message) {
		case WM_CREATE:{
			NONCLIENTMETRICS info;
			info.cbSize = sizeof(NONCLIENTMETRICS);
			if (SystemParametersInfo (SPI_GETNONCLIENTMETRICS, 0, &info, 0)) {
				hFont = CreateFontIndirect ((LOGFONT*)&info.lfMessageFont);
			}//取系统默认字体
			thread = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);//置顶窗口
			HINSTANCE hi = ((LPCREATESTRUCT) lParam)->hInstance;
			TxSum = CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, "已清除0个", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_READONLY, 8, 8, 216, 24, hwnd, HMENU(1001), hi, NULL);
			CreateWindow(WC_BUTTON, "开始", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 8, 40, 104, 32, hwnd, HMENU(1002), hi, NULL);
			CreateWindow(WC_BUTTON, "停止", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, 120, 40, 104, 32, hwnd, HMENU(1003), hi, NULL);
			CreateWindow(WC_BUTTON, "禁用cmd", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 8, 80, 104, 32, hwnd, HMENU(1004), hi, NULL);
			CreateWindow(WC_BUTTON, "解禁cmd", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 120, 80, 104, 32, hwnd, HMENU(1005), hi, NULL);
			HWND Grp = CreateWindow(WC_BUTTON, "停用程序（映像劫持）", WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 8, 120, 216, 104, hwnd, NULL, hi, NULL);
			CreateWindow(WC_STATIC, "输入程序名，需包含末尾扩展名exe", WS_CHILD | WS_VISIBLE, 16, 136, 200, 24, hwnd, NULL, hi, NULL);
			TxDsb = CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, "", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 16, 156, 200, 24, hwnd, HMENU(1006), hi, NULL);
			CreateWindow(WC_BUTTON, "停用", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 16, 188, 96, 28, hwnd, HMENU(1007), hi, NULL);
			CreateWindow(WC_BUTTON, "解禁", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 120, 188, 96, 28, hwnd, HMENU(1008), hi, NULL);
			TxOut = CreateWindow(STATUSCLASSNAME, TEXT("正常运行中"), WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, HMENU(1009), hi, NULL);
			EnumChildWindows(hwnd, SetWindowFont, (LPARAM)0);
			HMENU sys = GetSystemMenu(hwnd, FALSE);
			AppendMenu(sys, MF_STRING, 1, TEXT("关于(&C)"));
			focus = GetDlgItem(hwnd, 1003);
			SetFocus(focus);
			//卸载极域64位进程终止hook
			HMODULE hook = GetModuleHandle("LibTDProcHook64.dll");
			if (hook)FreeModule(hook);
			break;
		}
		case WM_COMMAND: {
			switch (LOWORD(wParam)) {
				case 1002: {
					bWorking = true;
					ResumeThread(thread);
					SetWindowText(TxOut, "正常运行中");
					break;
				}
				case 1003: {
					if(bWorking){
						SuspendThread(thread);
						SetWindowText(TxOut, "已暂停工作");
					}
					bWorking = false;
					break;
				}
				case 1004: {
					//HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System:DisableCMD->0
					HKEY retKey;
					DWORD value = 1;
					LONG ret = RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Windows\\System", 0, 0, 0, KEY_SET_VALUE | KEY_WOW64_32KEY, NULL, &retKey, NULL);
					ret = RegSetValueEx(retKey, "DisableCMD", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					RegCloseKey(retKey);
					break;
				}
				case 1005: {
					//HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System:DisableCMD->0
					HKEY retKey;
					DWORD value = 0;
					LONG ret = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Windows\\System", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					ret = RegSetValueEx(retKey, "DisableCMD", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					RegCloseKey(retKey);
					break;
				}
				case 1007: {
					int length = GetWindowTextLength(TxDsb);
					char szName[length+2];
					GetWindowText(TxDsb, szName, length+1);
					if(_stricmp(szName,"")==0){
						EDITBALLOONTIP ebt;
						ebt.cbStruct=sizeof(EDITBALLOONTIP);
						ebt.pszTitle=L"\x9519\x8bef\x0\x785c\x7825\x0\x0\x0";
						ebt.pszText=L"\x672a\x586b\x5199\x6587\x4ef6\x5185\x5bb9\x0";
						ebt.ttiIcon=TTI_ERROR;
						SendMessage(TxDsb,EM_SHOWBALLOONTIP,0,LPARAM(&ebt));
					}else{
						HKEY retKey;
						DWORD value = 0;
						string s = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
						s+=szName;
						LONG ret = RegCreateKeyEx(HKEY_LOCAL_MACHINE, s.c_str(), 0, 0, 0, KEY_SET_VALUE | KEY_WOW64_32KEY, NULL, &retKey, NULL);
						string c = "null";
						ret = RegSetValueEx(retKey, "debugger", 0, REG_SZ, (CONST BYTE*)c.c_str(), c.size() + 1);
						RegCloseKey(retKey);
					}
					break;
				}
				case 1008: {
					int length = GetWindowTextLength(TxDsb);
					char szName[length+2];
					GetWindowText(TxDsb, szName, length+1);
					if(_stricmp(szName,"")==0){
						EDITBALLOONTIP ebt;
						ebt.cbStruct=sizeof(EDITBALLOONTIP);
						ebt.pszTitle=L"\x9519\x8bef\x0\x785c\x7825\x0\x0\x0";
						ebt.pszText=L"\x672a\x586b\x5199\x6587\x4ef6\x5185\x5bb9\x0";
						ebt.ttiIcon=TTI_ERROR;
						SendMessage(TxDsb,EM_SHOWBALLOONTIP,0,LPARAM(&ebt));
					}else{
						//HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System:DisableCMD->0
						HKEY retKey;
						string s = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
						s+=szName;
						LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, s.c_str(), 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
						RegDeleteValue(retKey, "debugger");
						RegCloseKey(retKey);
					}
					break;
				}
			}
			return 0;
		}
		case WM_SYSCOMMAND:
			switch (wParam) {
				case 1: 
					MessageBox(hwnd, "CMDKiller v1.0\n作者：小流汗黄豆\n注意：若开启后某些软件无法正常运行，请停止本软件", "关于", MB_OK | MB_ICONINFORMATION);
			}
			return DefWindowProc(hwnd,Message,wParam,lParam);
		case WM_ACTIVATE: {
			if (LOWORD(wParam) == WA_INACTIVE) {
				if (GetWindowLong(hwnd, GWL_STYLE)&WS_VISIBLE) {
					focus = GetFocus();
					char c[7];
					GetClassName(focus, c, 7);
					if (_stricmp(c, "Button") == 0) {
						LONG style = GetWindowLong(focus, GWL_STYLE);
						if ((style & BS_AUTOCHECKBOX) != BS_AUTOCHECKBOX)
							SendMessage(focus, BM_SETSTYLE, 0, TRUE);
					}
				}
			} else {
				SetFocus(focus);
				char c[7];
				GetClassName(focus, c, 7);
				if (_stricmp(c, "Button") == 0) {
					LONG style = GetWindowLong(focus, GWL_STYLE);
					if ((style & BS_AUTOCHECKBOX) != BS_AUTOCHECKBOX)
						SendMessage(focus, BM_SETSTYLE, BS_DEFPUSHBUTTON, TRUE);
				}
			}
			return FALSE;
		}
	case WM_LBUTTONDOWN:
		//实现空白处随意拖动
		SendMessage(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
		break;
		
		/* Upon destruction, tell the main thread to stop */
		case WM_DESTROY: {
			PostQuitMessage(0);
			break;
		}
		
		/* All other messages (a lot of them) are processed using default procedures */
	default:
		return DefWindowProc(hwnd, Message, wParam, lParam);
	}
	return 0;
}

/* The 'main' function of Win32 GUI programs: this is where execution starts */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	WNDCLASSEX wc; /* A properties struct of our window */
	HWND hwnd; /* A 'HANDLE', hence the H, or a pointer to our window */
	MSG msg; /* A temporary location for all messages */
	
	/* zero out the struct and set the stuff we want to modify */
	memset(&wc,0,sizeof(wc));
	wc.cbSize		 = sizeof(WNDCLASSEX);
	wc.lpfnWndProc	 = WndProc; /* This is where we will send messages to */
	wc.hInstance	 = hInstance;
	wc.hCursor		 = LoadCursor(NULL, IDC_ARROW);
	
	/* White, COLOR_WINDOW is just a #define for a system color, try Ctrl+Clicking it */
	wc.hbrBackground = (HBRUSH)COLOR_WINDOW;
	wc.lpszClassName = "CMDKillerClass";
	wc.hIcon		 = LoadIcon(hInstance, "A"); /* Load a standard icon */
	wc.hIconSm		 = LoadIcon(hInstance, "A"); /* use the name "A" to use the project icon */
	
	if(!RegisterClassEx(&wc)) {
		MessageBox(NULL, "Window Registration Failed!","Error!",MB_ICONEXCLAMATION|MB_OK);
		return 0;
	}
	
	hwnd = CreateWindowEx(WS_EX_CLIENTEDGE | WS_EX_TOPMOST,"CMDKillerClass","CMD Killer",(WS_OVERLAPPEDWINDOW | WS_VISIBLE)^WS_MAXIMIZEBOX ^ WS_SIZEBOX,
		CW_USEDEFAULT, /* x */
		CW_USEDEFAULT, /* y */
		242, /* width */
		280, /* height */
		NULL,NULL,hInstance,NULL);
	
	if(hwnd == NULL) {
		MessageBox(NULL, "Window Creation Failed!","Error!",MB_ICONEXCLAMATION|MB_OK);
		return 0;
	}
	
	ShowWindow(hwnd, nCmdShow);
	UpdateWindow(hwnd);
	/*
	  This is the heart of our program where all input is processed and
	  sent to WndProc. Note that GetMessage blocks code flow until it receives something, so
	  this loop will not produce unreasonably high CPU usage
	 */
	while (GetMessage(&msg, NULL, 0, 0) > 0) { /* If no error is received... */
		if (!IsDialogMessage(hwnd, &msg)) {
			TranslateMessage(&msg); /* Translate key codes to chars if present */
			DispatchMessage(&msg); /* Send it to WndProc */
		}
	}
	return msg.wParam;
}

