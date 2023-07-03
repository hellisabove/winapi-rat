#include <Windows.h>

BOOL APIENTRY DllMain(HMODULE Base, DWORD Callback, LPVOID Param) {
	switch (Callback) {
	case DLL_PROCESS_ATTACH:
		
		break;
	case DLL_PROCESS_DETACH:

		break;
	default:

		break;
	}
	return 1;
}

extern "C" __declspec(dllexport) int FunEntry() {
	char exe[MAX_PATH + 1];
	GetModuleFileNameA(0, exe, sizeof(exe));
	MessageBoxA(0, exe, "I am inside: ", 0);
	return 0;
}