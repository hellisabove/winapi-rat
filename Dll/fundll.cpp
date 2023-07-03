#include "tools.h"
BOOL was_dllmain_called = FALSE;
DWORD dll_param;

LPSTR target_path = "C:\\Windows\\System32\\conhost.exe";

extern "C" __declspec(dllexport) void FunEntry() {
	char dll_path[MAX_PATH];
	DWORD ret = GetModuleFileNameA((HINSTANCE)dll_param, dll_path, MAX_PATH);
	char test[1024];
	wsprintfA(test, "%s", dll_path);
	MessageBoxA(0, test, "", 0);
	// inject dll
	Tools::AutoInject(target_path, dll_path);
}

BOOL APIENTRY DllMain(HMODULE Base, DWORD Callback, LPVOID Param) {
	dll_param = (DWORD)Base;
	was_dllmain_called = TRUE;

	switch (Callback) {
	case DLL_PROCESS_ATTACH:

		break;
	case DLL_PROCESS_DETACH:

		break;
	}
	return TRUE;
}

extern "C" __declspec(dllexport) void MainBitch() {
	if (was_dllmain_called) {
		while (TRUE) {
			char exe[MAX_PATH + 1];
			GetModuleFileNameA(0, exe, sizeof(exe));
			MessageBoxA(0, exe, "I am inside: ", 0);
		}
	} else {
		MessageBoxA(NULL, "DLLMain was not called", NULL, 0);
	}
}