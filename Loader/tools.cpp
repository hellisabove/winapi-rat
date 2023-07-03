#include "tools.h"
#include <Windows.h>

PVOID Tools::GetImageBase() {
	PWORD virtual_address = PWORD(&GetImageBase);
	PDWORD image_base = NULL;

	__asm {
		mov eax, virtual_address
		and eax, 0xFFFF0000
		IterateImage:
		cmp WORD PTR[eax], 0x5A4D
			je EndIteration
			sub eax, 0x00010000
			jmp IterateImage
			EndIteration:
		mov[image_base], eax
	}

	return image_base;
}

PBYTE Tools::ExtractDllFile(PBYTE module_base, PDWORD module_size) {
	PIMAGE_DOS_HEADER image_dos_header = (PIMAGE_DOS_HEADER)(module_base);
	if (image_dos_header->e_magic == IMAGE_DOS_SIGNATURE) {
		PIMAGE_NT_HEADERS image_nt_headers = (PIMAGE_NT_HEADERS)(module_base + image_dos_header->e_lfanew);
		if (image_nt_headers->Signature == IMAGE_NT_SIGNATURE) {
			PIMAGE_SECTION_HEADER first_section = (PIMAGE_SECTION_HEADER)(IMAGE_FIRST_SECTION(image_nt_headers));
			PIMAGE_SECTION_HEADER dll_section = (PIMAGE_SECTION_HEADER)(first_section + image_nt_headers->FileHeader.NumberOfSections - 1);
			if (dll_section != ERROR) {
				*module_size = dll_section->Misc.VirtualSize;
				return RtlOffsetToPointer(module_base, dll_section->VirtualAddress);
			}
		}
	}
}