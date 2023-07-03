#include <Windows.h>

#pragma once

namespace Tools {
	int AutoInject(LPSTR target_process, LPCSTR payload);
}