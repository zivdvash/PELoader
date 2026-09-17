#include <iostream>
#include <Windows.h>
#include <string>

int main()
{
    std::string pe_file_name = "kernel32.dll";
    HMODULE image_base_address = LoadLibraryA(pe_file_name.c_str());
    if (!image_base_address)
    {
        std::cerr << "Failed to load module: " << pe_file_name << " :( \n";
        return 1;
    }
    std::cout << "The PE base address: " << image_base_address << "\n";
    PIMAGE_DOS_HEADER pointer_dos_header = (PIMAGE_DOS_HEADER)image_base_address;
    std::cout << "The PE magic: 0x" << std::hex << std::uppercase << pointer_dos_header->e_magic << "\n";
    return 0;
}
