#include <iostream>
#include <Windows.h>
#include <string>

void PrintExportedFunctionNames(HMODULE imageBaseAddress, PIMAGE_NT_HEADERS ntHeaders)
{
	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)imageBaseAddress + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD numberOfNames = imageExportDirectory->NumberOfNames;
	DWORD* exportNameRVAs = (DWORD*)((BYTE*)imageBaseAddress + imageExportDirectory->AddressOfNames);
	std::cout << "The functions of the DLL:" << "\n";
	for (DWORD i = 0; i < numberOfNames; i++)
	{
		std::cout << ((char*)imageBaseAddress + exportNameRVAs[i]) << "\n";
	}
}
void PrintPEArchitecture(PIMAGE_NT_HEADERS ntHeaders)
{
	if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		std::cout << "the PE is 64-bit\n";
	else if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		std::cout << "the PE is 32-bit\n";
}
int main()
{
	const std::string peFileName = "kernel32.dll";
	HMODULE imageBaseAddress = LoadLibraryA(peFileName.c_str());


	if (!imageBaseAddress)
	{
		std::cerr << "Failed to load module: " << peFileName << " :( \n";
		return 1;
	}

	//mission 1
	std::cout << "The PE base address: " << imageBaseAddress << "\n";
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBaseAddress;
	std::cout << "The PE magic: 0x" << std::hex << std::uppercase << dosHeader->e_magic << "\n";

	//mission 2
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dosHeader + dosHeader->e_lfanew);
	PrintPEArchitecture(ntHeaders);

	//mission 3
	PrintExportedFunctionNames(imageBaseAddress, ntHeaders);
	FreeLibrary(imageBaseAddress);
	return 0;

}