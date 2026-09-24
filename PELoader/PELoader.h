#include <Windows.h>
#include <vector>
#include <string>
#include <cstring>

enum PELoaderError {
	DLL_BUFFER_IS_NULL,
	PELOADER_INVALID_DOS,
	PELOADER_INVALID_NT,
	PELOADER_NULL_POINTER,
	PELOADER_MEMORY_ALLOCATION_FAILED,
	PELOADER_ENTRY_POINT_CALL_FAILED,
	PELOADER_RELOCATION_FAILED,
	PELOADER_NAME_NOT_FOUND,
	PELOADER_IMPORT_LOAD_FAILED,
};
struct ExportTables { 
	PIMAGE_EXPORT_DIRECTORY exportDirectory;
	WORD* ordinals;
	DWORD* names;
	DWORD* functions;
};

class PELoader {

	public:
		/*
		* main purpose: managing the overall load process 
		* 
		* @param: dllBuffer: base address of the demanded PE file that needs to be loaded 
		* 
		* helper functions: validatePE(class PELoader), VirtualAlloc(windows api), memcpy(C standart Library) ,
		*					mapSections(class PELoader), activateRelocations(class PELoader), importsHandling(class PELoader), 
		*					callEntryPoint(class PELoader)
		* 
		* @return: pointer to base address of the loaded PE file
		*/
		BYTE* loadLibrary(BYTE* dllBuffer){
			PIMAGE_NT_HEADERS ntHeader = validatePE(dllBuffer);
			BYTE* pImageBase = (BYTE*)VirtualAlloc((VOID*)ntHeader->OptionalHeader.ImageBase, ntHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!pImageBase) {
				pImageBase = (BYTE*)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if (!pImageBase)
					throw PELOADER_MEMORY_ALLOCATION_FAILED;
			}
			memcpy(pImageBase, dllBuffer, ntHeader->OptionalHeader.SizeOfHeaders);
			mapSections(ntHeader, dllBuffer, pImageBase);
			if ((INT_PTR)pImageBase != ntHeader->OptionalHeader.ImageBase){
				activateRelocations(pImageBase, ntHeader);
			}
			importsHandling(pImageBase, ntHeader);
			callEntryPoint(pImageBase, ntHeader, DLL_PROCESS_ATTACH);
			return pImageBase;
		}
		/*
		* main purpose: managing the overall free process
		*
		* @param: loadAddress: base address of the loaded PE file
		*
		* helper functions: FreeLibrary(windows api),VirtualFree(windows api), callEntryPoint(class PELoader)
		*
		* @return: nothing :)
		*/
		void freeLibrary(BYTE* loadAddress){
			if (loadAddress == nullptr){
				throw PELOADER_NULL_POINTER;
			}
			PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)loadAddress;
			callEntryPoint(loadAddress, (PIMAGE_NT_HEADERS)(loadAddress + dosHeader->e_lfanew), DLL_PROCESS_DETACH);
			for (HMODULE module : importedModules){
				FreeLibrary(module);
			}
			importedModules.clear();
			VirtualFree(loadAddress, 0, MEM_RELEASE);
		}
		/*
		* main purpose: find and return the address of requested function from the loaded PE file
		*
		* @param: moduleAddress: base address of the loaded PE file 
		* @param: funcName: requsted function to find and return
		* 
		* helper functions: getExportTables(class PELoader),binarySearch(class PELoader), isForwarded(class PELoader),exportForwarding(class PELoader)
		*
		* @return: pointer base address of the requested function 
		*/
		BYTE* getProcAddress(BYTE* moduleAddress, const char* funcName){
			ExportTables exports = getExportTables(moduleAddress);
			DWORD nameIndex = binarySearch((BYTE*)moduleAddress, exports.names, exports.exportDirectory->NumberOfNames, funcName);
			WORD functionIndex = exports.ordinals[nameIndex];
			DWORD functionRva = exports.functions[functionIndex];
			if (isForwarded((BYTE*)moduleAddress, functionRva)) {
				return exportForwarding((BYTE*)moduleAddress, functionRva);
			}
			return (BYTE*)moduleAddress + functionRva;
		}

	private:
		std::vector<HMODULE> importedModules; // used for releasing the imported modules later

		PIMAGE_NT_HEADERS validatePE(BYTE* dllBuffer){
			if (dllBuffer == nullptr){
				throw DLL_BUFFER_IS_NULL;
			}
			PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
			if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE){
				throw PELOADER_INVALID_DOS;
			}
			PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(dllBuffer + dosHeader->e_lfanew);
			if (ntHeader->Signature != IMAGE_NT_SIGNATURE){
				throw PELOADER_INVALID_NT;
			}
			return ntHeader;
		}
		/*
		* main purpose: copying the sections to the correct place in the memory
		*
		* @param: ntHeader: the NT header of the PE file
		* @param: dllBuffer: base address of the demanded PE file that needs to be loaded
		* @param: pImageBase: base address of the loaded PE file
		* 
		* helper functions: memcpy(C standard Library)
		*
		* @return: nothing :)
		*/
		void mapSections(PIMAGE_NT_HEADERS ntHeader, BYTE* dllBuffer, BYTE* pImageBase)
		{
			PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)ntHeader + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeader->FileHeader.SizeOfOptionalHeader);
			for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++){
				PIMAGE_SECTION_HEADER currentSection = &sectionHeader[i];
				BYTE* destAddress = pImageBase + currentSection->VirtualAddress;
				BYTE* srcAddress = dllBuffer + currentSection->PointerToRawData;
				memcpy(destAddress, srcAddress, currentSection->SizeOfRawData);
			}
		}
		/*
		* main purpose: find and run the main function of the PE file 
		*
		* @param: pImageBase: base address of the loaded PE file
		* @param: ntHeader: the NT header of the PE file
		* @param: reason: DLL_PROCESS_ATTACH/DLL_PROCESS_DETACH - two flags that indicates if the entry called for running or cleaning
		* 
		* helper functions: freeLibrary(class PELoader)
		*
		* @return: nothing :)
		*/
		void callEntryPoint(BYTE* pImageBase, PIMAGE_NT_HEADERS ntHeader, DWORD reason)
		{
			if (ntHeader->OptionalHeader.AddressOfEntryPoint == 0){
				return;
			}
			typedef BOOL(WINAPI* DllEntryPoint)(HINSTANCE, DWORD, LPVOID);
			BYTE* entryPointAddress = pImageBase + ntHeader->OptionalHeader.AddressOfEntryPoint;
			DllEntryPoint entryPoint = (DllEntryPoint)(entryPointAddress);
			BOOL result = entryPoint((HINSTANCE)pImageBase, reason, nullptr);
			if (reason == DLL_PROCESS_ATTACH && !result){
				freeLibrary(pImageBase);
				throw PELOADER_ENTRY_POINT_CALL_FAILED;
			}
		}
		/*
		* main purpose: handle relocation if needed (in case the pe file can't be loaded in the desired address)
		*
		* @param: pImageBase: base address of the loaded PE file
		* @param: ntHeader: the NT header of the PE file
		* 
		* helper functions: NONE
		* 
		* @return: nothing :)
		*/
		void activateRelocations(BYTE* imageBase, PIMAGE_NT_HEADERS ntHeader){
			IMAGE_DATA_DIRECTORY relocationDirectory = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			PIMAGE_BASE_RELOCATION baseRelocation = (PIMAGE_BASE_RELOCATION)(imageBase + relocationDirectory.VirtualAddress);
			DWORD sizeCounter = 0;
			INT_PTR delta = (INT_PTR)imageBase - ntHeader->OptionalHeader.ImageBase;
			while (relocationDirectory.Size > sizeCounter){
				sizeCounter += baseRelocation->SizeOfBlock;
				WORD* entries = (WORD*)((BYTE*)baseRelocation + sizeof(IMAGE_BASE_RELOCATION));
				size_t entriesCount = (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				for (size_t i = 0; i < entriesCount; i++){
					WORD offset = entries[i] & 0xFFF;
					WORD type = entries[i] >> 12;
					BYTE* addressToRelocate = imageBase + baseRelocation->VirtualAddress + offset;
					switch (type)
					{
					case IMAGE_REL_BASED_ABSOLUTE:
						break;

					case IMAGE_REL_BASED_HIGHLOW:
						*(DWORD*)addressToRelocate += (DWORD)delta;
						break;

					case IMAGE_REL_BASED_DIR64:
						*(ULONGLONG*)addressToRelocate += (ULONGLONG)delta;
						break;

					default:
						throw PELOADER_RELOCATION_FAILED;
					}
				}
				baseRelocation = (PIMAGE_BASE_RELOCATION)((BYTE*)baseRelocation + baseRelocation->SizeOfBlock);
				if (sizeCounter > relocationDirectory.Size) {
					throw PELOADER_RELOCATION_FAILED;
				}
			}

		}
		/*
		* main purpose: handle the imports of the loaded PE file 
		*
		* @param: pImageBase: base address of the loaded PE file
		* @param: ntHeader: the NT header of the PE file
		* 
		* helper functions: isImportByOrdinal(class PELoader),getImportOrdinal(class PELoader), resolveExportByOrdinal(class PELoader),
		*					getProcAddress(class PELoader)
		*
		* @return: nothing :)
		*/
		void importsHandling(BYTE* pImageBase, PIMAGE_NT_HEADERS ntHeader){
			DWORD importRva = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
			if (importRva == 0)
				return;
			PIMAGE_IMPORT_DESCRIPTOR imageImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pImageBase + importRva);
			while (imageImportDirectory->Name != 0){
				HMODULE pImportedImageBase = LoadLibraryA((LPCSTR)(pImageBase + imageImportDirectory->Name));
				if (!pImportedImageBase)
					throw PELOADER_IMPORT_LOAD_FAILED;
				importedModules.push_back(pImportedImageBase);
				DWORD originalThunkRva = imageImportDirectory->OriginalFirstThunk;
				if (originalThunkRva == 0)
					originalThunkRva = imageImportDirectory->FirstThunk;
				PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)(pImageBase + originalThunkRva);
				PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)pImageBase + imageImportDirectory->FirstThunk);

				while (originalThunk->u1.AddressOfData != 0){
					BYTE* functionAddress;
					if (isImportByOrdinal(ntHeader, originalThunk)){
						WORD ordinal = getImportOrdinal(ntHeader, originalThunk);
						functionAddress = resolveExportByOrdinal((BYTE*)pImportedImageBase, ordinal);
					}
					else{
						PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(pImageBase + originalThunk->u1.AddressOfData);
						functionAddress = getProcAddress((BYTE*)pImportedImageBase, (const char*)importByName->Name);
					}
					thunk->u1.Function = (ULONG_PTR)functionAddress;
					originalThunk++;
					thunk++;
				}
				imageImportDirectory++;
			}

		}
		bool isImportByOrdinal(PIMAGE_NT_HEADERS ntHeader, PIMAGE_THUNK_DATA thunk) {
			if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
				return IMAGE_SNAP_BY_ORDINAL32(thunk->u1.Ordinal);
			if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
				return IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal);
			throw PELOADER_INVALID_NT;
		}

		ExportTables getExportTables(BYTE* moduleBase){
			PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
			PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);
			PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)moduleBase + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			return{
				exportDirectory,
				(WORD*)((BYTE*)moduleBase + exportDirectory->AddressOfNameOrdinals),
				(DWORD*)((BYTE*)moduleBase + exportDirectory->AddressOfNames),
				(DWORD*)((BYTE*)moduleBase + exportDirectory->AddressOfFunctions)
			};
		}

		WORD getImportOrdinal(PIMAGE_NT_HEADERS ntHeader, PIMAGE_THUNK_DATA thunk){
			if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
				return IMAGE_ORDINAL32(thunk->u1.Ordinal);
			if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
				return IMAGE_ORDINAL64(thunk->u1.Ordinal);
			throw PELOADER_INVALID_NT;
		}
		/*
		* main purpose: handle the search of the requested imported function if its ordinal based 
		*
		* @param: moduleBase: base address of the imported PE file
		* @param: ordinal: the ordinal of the function we are looking for
		*
		* helper functions: getExportTables(class PELoader), isForwarded(class PELoader), exportForwarding(class PEloader)
		*
		* @return: pointer to base address of the requested function
		*/
		BYTE* resolveExportByOrdinal(BYTE* moduleBase, WORD ordinal){
			ExportTables exports = getExportTables(moduleBase);
			DWORD functionIndex = ordinal - exports.exportDirectory->Base;
			DWORD functionRva = exports.functions[functionIndex];
			if (isForwarded(moduleBase, functionRva)) {
				return exportForwarding(moduleBase, functionRva);
			}
			return moduleBase + functionRva;
		}

		DWORD binarySearch(BYTE* imageBase, DWORD* names, DWORD numberOfNames, const char* nameToFind){
			LONG low = 0;
			LONG high = numberOfNames - 1;
			while (low <= high){
				LONG mid = low + (high - low) / 2;
				const char* currentName = (const char*)(imageBase + names[mid]);
				int cmp = strcmp(currentName, nameToFind);
				if (cmp == 0){
					return mid;
				}
				if (cmp < 0){
					low = mid + 1;
				}
				else{
					high = mid - 1;
				}
			}
			throw PELOADER_NAME_NOT_FOUND;
		}
		/*
		* main purpose: handle export forwarding (recursive function - functions can be forwarded more than once)
		*
		* @param: pImportedImageBase: base address of the imported PE file
		* @param: functionRva: RVA to the forwarded string(can be ordinal or name - handled differently)
		* 
		* helper functions: LoadLibraryA(windows api),resolveExportByOrdinal(class PELoader), getProcAddress(class PEloader)
		*
		* @return: pointer of the requested function
		*/
		BYTE* exportForwarding(BYTE* pImportedImageBase, DWORD functionRva) {
			std::string forwarder = (const char*)((BYTE*)pImportedImageBase + functionRva);
			size_t dot = forwarder.find('.');
			std::string dllName = forwarder.substr(0, dot);
			std::string functionName = forwarder.substr(dot + 1);
			HMODULE forwardedModule = LoadLibraryA(dllName.c_str());
			if (!forwardedModule)
				throw PELOADER_IMPORT_LOAD_FAILED;
			importedModules.push_back(forwardedModule);
			BYTE* forwardedFunction;
			if (!functionName.empty() && functionName[0] == '#'){
				WORD ordinal = (WORD)std::stoi(functionName.substr(1));
				forwardedFunction = resolveExportByOrdinal((BYTE*)forwardedModule, ordinal);
			}
			else{
				forwardedFunction = getProcAddress((BYTE*)forwardedModule, functionName.c_str());
			}
			return forwardedFunction;
		}

		bool isForwarded(BYTE* moduleBase, DWORD functionRva){
			PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
			PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);
			DWORD exportRva = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			DWORD exportSize = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
			if (functionRva >= exportRva && functionRva < exportRva + exportSize){
				return true;
			}
			return false;
		}

};
