#include <Windows.h>
#include <iostream>
#include <stdio.h>


struct PE {
	DWORD64 base;
	DWORD64 entry = NULL;
};

typedef BOOL(WINAPI* pDLLEntry)(HINSTANCE dll, DWORD reason, LPVOID reserved);
typedef BOOL(WINAPI* pEXEEntry)();


#include "PE Mapper.hpp"


int main(int argc, char* argv[]) {
	
	if (argc < 3) {
		printf("[-] Usage : %s [DLL|EXE] <PE Path>\n", argv[0]);
		return 1;
	}

	HANDLE hPE = ::CreateFileA(argv[2], GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPE == INVALID_HANDLE_VALUE) {
		printf("[-] Unable to open PE.\n");
		return 1;
	}

	DWORD pe_size = ::GetFileSize(hPE, NULL);
	void* pe_content = ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, pe_size);
	::ReadFile(hPE, pe_content, pe_size, NULL, NULL);
	::CloseHandle(hPE);
	

	PE pe = MapPE((BYTE*)pe_content);
	::HeapFree(::GetProcessHeap(), NULL, pe_content);

	if (!strcmp(argv[1], "DLL") || !strcmp(argv[1], "dll")) {
		pDLLEntry dll_entry_addr = (pDLLEntry)pe.entry;
		// printf("dll_entry_addr : %p", dll_entry_addr);
		dll_entry_addr((HINSTANCE)pe.base, DLL_PROCESS_ATTACH, 0);
	}
	else if(!strcmp(argv[1], "EXE") || !strcmp(argv[1], "exe")) {
		pEXEEntry exe_entry_addr = (pEXEEntry)pe.entry;
		// printf("exe_entry_addr : %p", exe_entry_addr);
		exe_entry_addr();
	}
	else {
		printf("[-] Invalid PE type.\n");
	}

	::Sleep(INFINITE);
	::VirtualFree((LPVOID)pe.base, NULL, MEM_RELEASE);

	return 0;
}
