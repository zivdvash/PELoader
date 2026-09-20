#include <Windows.h>


class PELoader {

	public:
		BYTE* loadLibrary(BYTE* dllBuffer) {
			if (dllBuffer == nullptr) {
				return nullptr;
			}
			PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
			if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
				return nullptr;
			}
			PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(dllBuffer + dosHeader->e_lfanew);
			if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
			{
				return nullptr;
			}
	
			LPVOID imageBase = VirtualAlloc((VOID*)ntHeader->OptionalHeader.ImageBase, ntHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			BYTE* pImageBase = (BYTE*)imageBase;
			
			if (!imageBase) {
				return nullptr;
			}
			PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)ntHeader + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeader->FileHeader.SizeOfOptionalHeader);
			memcpy(imageBase, dllBuffer, ntHeader->OptionalHeader.SizeOfHeaders);
			for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
			{
				PIMAGE_SECTION_HEADER currentSection = &sectionHeader[i];
				if (currentSection->PointerToRawData == 0){
					continue;
				}
				BYTE* destAddress = pImageBase + currentSection->VirtualAddress;
				BYTE* srcAddress = dllBuffer + currentSection->PointerToRawData;
				memcpy(destAddress, srcAddress, currentSection->SizeOfRawData);
			}
		};
		void freeLibrary(BYTE* loadAddress) {
			if (loadAddress != nullptr)
			{
				VirtualFree(loadAddress, 0, MEM_RELEASE);
			}
		};
		BYTE* getProcAddress(BYTE* moduleAddress, const char* funcName) {};
		
};
