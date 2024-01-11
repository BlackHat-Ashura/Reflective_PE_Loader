


PE MapPE(BYTE* pe_content) {
	////////// Mapping PE Start //////////

	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pe_content;
	IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pe_content + pDosHdr->e_lfanew);

	DWORD ImageSize = pNTHdr->OptionalHeader.SizeOfImage;
	DWORD64 ImageBase = pNTHdr->OptionalHeader.ImageBase;
	void* pe_base = ::VirtualAlloc(NULL, ImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	DWORD64 ImageBaseDifference = (DWORD64)pe_base - ImageBase; // For Base Relocations
	// printf("Difference : %p\n", ImageBaseDifference);
	
	DWORD HdrSize = pNTHdr->OptionalHeader.SizeOfHeaders;
	std::memcpy(pe_base, pe_content, HdrSize); // Mapped all Headers

	WORD OptHdrSize = pNTHdr->FileHeader.SizeOfOptionalHeader;
	IMAGE_SECTION_HEADER* pSectionTable = (IMAGE_SECTION_HEADER*)((DWORD64)&(pNTHdr->OptionalHeader) + OptHdrSize);
	DWORD SectionCount = pNTHdr->FileHeader.NumberOfSections;
	for (int i = 0; i < SectionCount; i++) {
		// printf("Name : %s\n", pSectionTable[i].Name);
		void* section_source_address = (void*)(pe_content + pSectionTable[i].PointerToRawData);
		void* section_destination_address = (void*)((DWORD64)pe_base + pSectionTable[i].VirtualAddress);
		std::memcpy(section_destination_address, section_source_address, pSectionTable[i].SizeOfRawData);
	} // Mapped all Sections

	////////// Mapping PE End //////////

	////////// Fixing PE Import Table Start //////////
	
	IMAGE_DATA_DIRECTORY* pImportDataDir = &pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	IMAGE_IMPORT_DESCRIPTOR* pImportDir = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD64)pe_base + pImportDataDir->VirtualAddress);

	while (pImportDir->Name) {
		LPCSTR library_name = (LPCSTR)((DWORD64)pe_base + pImportDir->Name);
		HMODULE hLibrary = ::LoadLibraryA(library_name);
		// printf("%s\n", library_name);
		
		if (hLibrary) {
			IMAGE_THUNK_DATA64* pThunk = (IMAGE_THUNK_DATA64*)((DWORD64)pe_base + pImportDir->FirstThunk);
			while (*(DWORD64*)pThunk){
				// Refer documentation for bitmasks in the below code
				if (*(DWORD64*)pThunk & (DWORD64)1 << 63) {
					// Import by ordinal
					// printf("\t%p\n", *(DWORD64*)pThunk & 0xffff);
					*(DWORD64*)pThunk = (DWORD64)::GetProcAddress(hLibrary, (LPCSTR)(*(DWORD64*)pThunk & 0xffff));
				}
				else {
					// Import by name
					// Adding size of WORD to ignore Hint and access Name data
					DWORD64* FuncAddr = (DWORD64*)((DWORD64)pe_base + *(DWORD64*)pThunk + sizeof(WORD));
					// printf("\t%X :", *(WORD*)((DWORD64)pe_base + *(DWORD64*)pThunk));
					*(DWORD64*)pThunk = (DWORD64)::GetProcAddress(hLibrary, (LPCSTR)FuncAddr);
					// printf("\t%s\n", (LPCSTR)FuncAddr);
				}
				pThunk++;
			}
		}

		::FreeLibrary(hLibrary);
		pImportDir++;
	}
	
	////////// Fixing PE Import Table End //////////

	////////// Fixing PE Base Relocations Start //////////
	
	if (ImageBaseDifference) {
		IMAGE_DATA_DIRECTORY* pRelocationDataDir = &pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		IMAGE_BASE_RELOCATION* pRelocationDir = (IMAGE_BASE_RELOCATION*)((DWORD64)pe_base + pRelocationDataDir->VirtualAddress);

		DWORD RelocSize = pRelocationDataDir->Size;
		DWORD RelocSizeCompleted = 0;
		// printf("RelocSize : %X\n\n", RelocSize);

		while (RelocSizeCompleted < RelocSize) {
			DWORD RelocPageRVA = pRelocationDir->VirtualAddress;
			DWORD reloc_count = (pRelocationDir->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			RelocSizeCompleted += sizeof(IMAGE_BASE_RELOCATION);
			WORD* curr_loc = (WORD*)((DWORD64)pRelocationDir + sizeof(IMAGE_BASE_RELOCATION));
			// printf("PageRVA : %X ; Size : %X\n", RelocPageRVA, reloc_count*2 + 8);
			for (DWORD i = 0; i < reloc_count; i++) {
				RelocSizeCompleted += sizeof(WORD);
				DWORD offset = *(curr_loc + i);
				WORD offsetType = offset >> 12;

				if (offsetType == 0) { continue; }
				offset = offset & 0x0fff;

				DWORD64* RelocDst = (DWORD64*)((DWORD64)pe_base + RelocPageRVA + offset);
				DWORD64 OrigAddress = *RelocDst;
				*RelocDst += ImageBaseDifference;
				// printf("Offset : %X ; Type : %d ; Original Address : %p ; New Address : %p\n", offset, offsetType, OrigAddress, *RelocDst);
			}
			// printf("\n========== Break ==========\n\n");

			pRelocationDir = (IMAGE_BASE_RELOCATION*)((DWORD64)pRelocationDir + pRelocationDir->SizeOfBlock);
		}
	}
	// printf("\n========== Finish ==========\n\n");
	
	////////// Fixing PE Base Relocations End //////////

	PE pe;
	pe.base = (DWORD64)pe_base;
	pe.entry = (DWORD64)((BYTE*)pe_base + pNTHdr->OptionalHeader.AddressOfEntryPoint);

	return pe;
}