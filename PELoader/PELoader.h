#include <Windows.h>

enum PELoaderError {
    DLL_BUFFER_IS_NULL,
    PELOADER_INVALID_DOS,
    PELOADER_INVALID_NT,
    PELOADER_NULL_POINTER,
    PELOADER_MEMORY_ALLOCATION_FAILED,
    PELOADER_ENTRY_POINT_CALL_FAILED
};

class PELoader {

public:
	BYTE* loadLibrary(BYTE* dllBuffer) {
		PIMAGE_NT_HEADERS ntHeader = ValidatePE(dllBuffer);
		BYTE* pImageBase = (BYTE*)VirtualAlloc((VOID*)ntHeader->OptionalHeader.ImageBase, ntHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!pImageBase) {
			throw PELOADER_MEMORY_ALLOCATION_FAILED;
		}
		memcpy(pImageBase, dllBuffer, ntHeader->OptionalHeader.SizeOfHeaders);
		MapSections(ntHeader, dllBuffer, pImageBase);
		CallEntryPoint(pImageBase, ntHeader, DLL_PROCESS_ATTACH);
		return pImageBase;
	}
	void freeLibrary(BYTE* loadAddress) {
		if (loadAddress == nullptr)
		{
			throw PELOADER_NULL_POINTER;
		}
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)loadAddress;
		CallEntryPoint(loadAddress, (PIMAGE_NT_HEADERS)(loadAddress + dosHeader->e_lfanew), DLL_PROCESS_DETACH);
		VirtualFree(loadAddress, 0, MEM_RELEASE);
	}
	BYTE* getProcAddress(BYTE* moduleAddress, const char* funcName) {};
private:
	PIMAGE_NT_HEADERS ValidatePE(BYTE* dllBuffer) {
		if (dllBuffer == nullptr) {
			throw DLL_BUFFER_IS_NULL;
		}
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			throw PELOADER_INVALID_DOS;
		}
		PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(dllBuffer + dosHeader->e_lfanew);
		if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
			throw PELOADER_INVALID_NT;
		}
		return ntHeader;
	}
	void MapSections(PIMAGE_NT_HEADERS ntHeader, BYTE* dllBuffer, BYTE* pImageBase)
	{
		PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)ntHeader + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeader->FileHeader.SizeOfOptionalHeader);
		for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
		{
			PIMAGE_SECTION_HEADER currentSection = &sectionHeader[i];
			if (currentSection->SizeOfRawData == 0) {
				continue;
			}
			BYTE* destAddress = pImageBase + currentSection->VirtualAddress;
			BYTE* srcAddress = dllBuffer + currentSection->PointerToRawData;
			memcpy(destAddress, srcAddress, currentSection->SizeOfRawData);
		}
	}
	void CallEntryPoint(BYTE* pImageBase, PIMAGE_NT_HEADERS ntHeader, DWORD reason)
	{
		if (ntHeader->OptionalHeader.AddressOfEntryPoint == 0) {
			return;
		}
		typedef BOOL(WINAPI* DllEntryPoint)(HINSTANCE, DWORD, LPVOID);
		BYTE* entryPointAddress = pImageBase + ntHeader->OptionalHeader.AddressOfEntryPoint;
		DllEntryPoint entryPoint = (DllEntryPoint)(entryPointAddress);
		BOOL result = entryPoint((HINSTANCE)pImageBase, reason, nullptr);
		if (reason == DLL_PROCESS_ATTACH && !result)
		{
			VirtualFree(pImageBase, 0, MEM_RELEASE);
			throw PELOADER_ENTRY_POINT_CALL_FAILED;
		}
	}
	
};