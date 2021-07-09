#include "dll_related_things.hpp"
#include <intrin.h>
#include <winternl.h>
#include <algorithm>
#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

// iterate over linked list and searches the dll with specific name
uint64_t parser::find_entry(uint64_t ldr_mod, uint64_t list_flink, const std::wstring& dll_name, uint64_t custom_offset)
{
    if (custom_offset == 0)
    {
        do
        {
            auto target_address = ldr_mod;

            asm_fn::x64_memcpy(&target_address, &target_address, sizeof(target_address));

            ldr_mod = target_address;
            target_address += offsetof(x64::LDR_DATA_TABLE_ENTRY, FullDllName);
            target_address += offsetof(x64::UNICODE_STRING, Buffer);

            asm_fn::x64_memcpy(&target_address, &target_address, sizeof(target_address));

            if (target_address != 0)
            {
                if (StrStrIW(reinterpret_cast<wchar_t*>(target_address), dll_name.c_str()))
                {
                    return ldr_mod;
                }
            }

        } while (list_flink != ldr_mod);

        return NULL;
    }
    else
    {
        do
        {
            auto target_address = ldr_mod;

            asm_fn::x64_memcpy(&target_address, &target_address, sizeof(target_address));

            ldr_mod = target_address;
            target_address -= custom_offset;
            target_address += offsetof(x64::LDR_DATA_TABLE_ENTRY, FullDllName);
            target_address += offsetof(x64::UNICODE_STRING, Buffer);

            asm_fn::x64_memcpy(&target_address, &target_address, sizeof(target_address));

            if (target_address != 0)
            {
                if (StrStrIW(reinterpret_cast<wchar_t*>(target_address), dll_name.c_str()))
                {
                    return ldr_mod;
                }
            }

        } while (list_flink != ldr_mod);

        return NULL;
    }
}

uint64_t parser::get_first_ldr_entry(uint32_t index)
{
    constexpr uint32_t module_list = 0x18;
    constexpr uint32_t module_list_flink = 0x18;
    bool found = false;

    uint64_t peb = asm_fn::get_x64_peb_address();
    uint64_t mod_list = peb + module_list;

    asm_fn::x64_memcpy(&mod_list, &mod_list, sizeof(mod_list));

    uint64_t list_flink = mod_list + module_list_flink + index * 0x10;

    asm_fn::x64_memcpy(&list_flink, &list_flink, sizeof(list_flink));

    return list_flink;
}

// get address of ldr entry by name
uint64_t parser::parse_ldr_entry(const std::wstring& dll_name)
{
    uint64_t list_flink = get_first_ldr_entry();
    uint64_t ldr_mod = list_flink;

    ldr_mod = find_entry(ldr_mod, list_flink, dll_name);

    if (ldr_mod == NULL)
    {
        return NULL;
    }

    return ldr_mod;
}

// get base address of dll
uint64_t parser::parse_dll_in_ldr_table(const std::wstring& dll_name)
{
    std::string ansi_dll_name = { dll_name.begin(), dll_name.end() };

    if (libraries.find(ansi_dll_name) != libraries.end())
    {
        return libraries.at(ansi_dll_name);
    }

    uint64_t dll_ptr;
    uint64_t ldr_entry = parse_ldr_entry(dll_name);

    if (ldr_entry == NULL)
    {
        return NULL;
    }

    auto target_address = ldr_entry;
    target_address = ldr_entry + offsetof(x64::LDR_DATA_TABLE_ENTRY, DllBase);

    asm_fn::x64_memcpy(&target_address, &dll_ptr, sizeof(dll_ptr));

    libraries.insert({ ansi_dll_name, dll_ptr });

    return libraries.at(ansi_dll_name);
}

parser::parser()
{
    std::vector<std::string> functions_to_find = { "LdrLoadDll", "RtlEqualUnicodeString", 
        "NtProtectVirtualMemory", "NtAllocateVirtualMemory", "NtWriteVirtualMemory", };

    if (parse_dll_in_ldr_table(L"ntdll.dll") == NULL)
    {
        throw std::exception("Cannot find ntdll.dll in LDR table");
    }

    uint64_t base_address = libraries.at("ntdll.dll");

    auto parsed_export = find_export_in_dll(base_address, functions_to_find);

    for (auto& entry : parsed_export)
    {
        functions.insert(std::move(entry));
    }
}

// parse export table of dll
std::vector<std::pair<std::string, uint64_t>> parser::find_export_in_dll(uint64_t base_address, const std::vector<std::string>& functions)
{
    std::vector<std::pair<std::string, uint64_t>> result;

    uint64_t target_address;
    DWORD virtual_address;

    LONG e_lfanew;
    target_address = base_address + offsetof(IMAGE_DOS_HEADER, e_lfanew);
    asm_fn::x64_memcpy(&target_address, &e_lfanew, sizeof(e_lfanew));

    uint64_t nt_header = base_address + e_lfanew;

    target_address = nt_header + offsetof(IMAGE_NT_HEADERS64, OptionalHeader);
    target_address = target_address + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
    target_address = target_address + offsetof(IMAGE_DATA_DIRECTORY, VirtualAddress);
    asm_fn::x64_memcpy(&target_address, &virtual_address, sizeof(virtual_address));

    uint64_t export_table = base_address + virtual_address;

    target_address = export_table + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNames);
    asm_fn::x64_memcpy(&target_address, &virtual_address, sizeof(virtual_address));

    uint64_t name_ptr = base_address + virtual_address;

    target_address = export_table + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNameOrdinals);
    asm_fn::x64_memcpy(&target_address, &virtual_address, sizeof(virtual_address));

    uint64_t ordinal_ptr = base_address + virtual_address;

    target_address = export_table + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfFunctions);
    asm_fn::x64_memcpy(&target_address, &virtual_address, sizeof(virtual_address));

    uint64_t func_table = base_address + virtual_address;

    DWORD number_of_functions;
    target_address = export_table + offsetof(IMAGE_EXPORT_DIRECTORY, NumberOfFunctions);
    asm_fn::x64_memcpy(&target_address, &number_of_functions, sizeof(number_of_functions));

    for (auto& element : functions)
    {
        for (auto j = 0u; j < number_of_functions; j++)
        {
            std::string api_name(MAX_PATH, 0);
            target_address = name_ptr + j * 4;

            asm_fn::x64_memcpy(&target_address, &virtual_address, sizeof(virtual_address));

            target_address = base_address + virtual_address;

            asm_fn::get_string(&target_address, api_name.data());

            if (StrStrIA(api_name.c_str(), element.c_str()))
            {
                target_address = ordinal_ptr + j * 2;
                uint16_t ord;

                asm_fn::x64_memcpy(&target_address, &ord, sizeof(ord));

                target_address = func_table + ord * 4;

                asm_fn::x64_memcpy(&target_address, &virtual_address, sizeof(virtual_address));

                api_name.erase(std::remove(api_name.begin(), api_name.end(), '\0'), api_name.end());

                result.push_back({ api_name, base_address + virtual_address });

                break;
            }
        }
    }

    return result;
}

uint64_t parser::get_function_address(std::string fn_name)
{
    return functions.at(fn_name);
}

uint64_t parser::get_library_address(std::string library_name)
{
    return libraries.at(library_name);
}