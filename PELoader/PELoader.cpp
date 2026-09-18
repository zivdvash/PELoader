#include <iostream>
#include <Windows.h>
#include <string>

int main()
{
    std::string pe_file_name = "kernel32.dll";
    HMODULE image_base_address = LoadLibraryA(pe_file_name.c_str());

    //mission 1
    if (!image_base_address)
    {
        std::cerr << "Failed to load module: " << pe_file_name << " :( \n";
        return 1;
    }
    std::cout << "The PE base address: " << image_base_address << "\n";
    PIMAGE_DOS_HEADER pointer_dos_header = (PIMAGE_DOS_HEADER)image_base_address;
    std::cout << "The PE magic: 0x" << std::hex << std::uppercase << pointer_dos_header->e_magic << "\n";

    //mission 2
    PIMAGE_NT_HEADERS pointer_nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)pointer_dos_header + pointer_dos_header->e_lfanew);
    if (pointer_nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        std::cout << "the base of the PE is 64\n";
    else if (pointer_nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        std::cout << "the base of the PE is 32\n";
    return 0;
}
