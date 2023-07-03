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
}

extern "C" __declspec(dllexport) int FunEntry() {
	return MessageBoxA(0, "Hello from C2", 0, 0);
}