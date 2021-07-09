#pragma once
#include <unordered_map>
#include <string>
#include <Windows.h>
#include <memory>
#include <vector>

#define STR_MERGE_IMPL(a, b) a##b
#define STR_MERGE(a, b) STR_MERGE_IMPL(a, b)
#define MAKE_PAD(size) STR_MERGE(_pad, __COUNTER__)[size]
#define DEFINE_MEMBER_N(type, name, offset) struct {unsigned char MAKE_PAD(offset); type name;}

#define LDRP_PROCESS_ATTACH_CALLED	0x000080000
#define LDRP_ENTRY_PROCESSED		0x000004000

// look in x64_shellcode.asm
namespace x64_shellcode
{
    extern "C" inline char get_x64_teb_address_shellcode[] =
        "\x65\x48\x8b\x04\x25\x30\x00\x00\x00\xcb";

    extern "C" inline char get_x64_peb_address_shellcode[] =
        "\x65\x48\x8b\x04\x25\x60\x00\x00\x00\xcb";

    extern "C" inline char x64_memcpy_shellcode[] =
        "\x8b\x4c\x24\x0c\x4c\x8b\x01\x8b\x54\x24"
        "\x10\x8b\x4c\x24\x14\x57\x56\x49\x8b\xf0"
        "\x48\x8b\xfa\xf3\xa4\x5e\x5f\xcb";

    extern "C" inline char get_string_shellcode[] =
        "\x48\x33\xc0\x8b\x4c\x24\x0c\x4c\x8b\x01"
        "\x44\x8b\x4c\x24\x10\x57\x56\x49\x8b\xf0"
        "\x49\x8b\xf8\x48\xc7\xc1\xff\xff\xff\xff"
        "\xf2\xae\x48\xf7\xd1\x49\x8b\xf9\xf3\xa4"
        "\x5e\x5f\xcb";

    inline char RtlEqualUnicodeStringHook[] =
        "\x48\x83\xec\x48\x66\x83\x39\x18\x45\x0f"
        "\xb6\xd8\x0f\x10\x05\x90\x00\x00\x00\x4c"
        "\x8b\xca\x0f\xb7\x05\x9e\x00\x00\x00\xf2"
        "\x0f\x10\x0d\x8e\x00\x00\x00\x4c\x8b\xd1"
        "\x0f\x11\x44\x24\x20\x66\x89\x44\x24\x38"
        "\xf2\x0f\x11\x4c\x24\x30\x75\x5b\x66\x83"
        "\x3a\x18\x75\x55\x45\x84\xc0\x74\x50\x4c"
        "\x8b\x41\x08\x33\xc9\x8b\xd1\x0f\x1f\x00"
        "\x0f\xb7\x44\x54\x20\x66\x41\x39\x04\x50"
        "\x75\x2f\x48\xff\xc2\x48\x83\xfa\x0c\x7c"
        "\xeb\x49\x8b\x51\x08\x0f\x1f\x80\x00\x00"
        "\x00\x00\x0f\xb7\x44\x4c\x20\x66\x39\x04"
        "\x4a\x75\x10\x48\xff\xc1\x48\x83\xf9\x0c"
        "\x7c\xec\x32\xc0\x48\x83\xc4\x48\xc3\x49"
        "\x8b\xca\x49\x8b\xd1\x45\x0f\xb6\xc3\x48"
        "\x8b\x05\x23\x00\x00\x00\x48\x83\xc4\x48"
        "\x48\xff\xe0\x4b\x00\x45\x00\x52\x00\x4e"
        "\x00\x45\x00\x4c\x00\x33\x00\x32\x00\x2e"
        "\x00\x44\x00\x4c\x00\x4c\x00\x00\x00\x00"
        "\x00\xff\xff\xff\xff\xff\xff\xff\xff";

    extern "C" inline char x64_api_call_shellcode[] =
        "\x89\x15\x86\x01\x00\x00\x89\x0d\x84\x01"
        "\x00\x00\x48\x8b\xc4\x48\x83\xe0\x0f\x48"
        "\x83\xf8\x00\x74\x03\x48\x2b\xe0\x89\x05"
        "\x62\x01\x00\x00\x41\x52\x41\x53\x41\x54"
        "\x41\x55\x41\x56\x41\x57\x44\x8b\x6c\x04"
        "\x3c\x4d\x8b\x6d\x08\x49\xc7\xc7\x28\x00"
        "\x00\x00\x44\x89\x3d\x43\x01\x00\x00\x48"
        "\x85\xc9\x74\x1a\x48\x83\xf9\x01\x74\x1c"
        "\x48\x83\xf9\x02\x74\x28\x48\x83\xf9\x03"
        "\x74\x38\x48\x83\xf9\x04\x74\x4c\x7f\x68"
        "\x49\x2b\xe7\xe9\xf6\x00\x00\x00\x44\x8b"
        "\x15\x19\x01\x00\x00\x49\x8b\x0a\x49\x2b"
        "\xe7\xe9\xe4\x00\x00\x00\x44\x8b\x15\x07"
        "\x01\x00\x00\x49\x8b\x0a\x49\x8b\x52\x08"
        "\x49\x2b\xe7\xe9\xce\x00\x00\x00\x44\x8b"
        "\x15\xf1\x00\x00\x00\x49\x8b\x0a\x49\x8b"
        "\x52\x08\x4d\x8b\x42\x10\x49\x2b\xe7\xe9"
        "\xb4\x00\x00\x00\x44\x8b\x15\xd7\x00\x00"
        "\x00\x49\x8b\x0a\x49\x8b\x52\x08\x4d\x8b"
        "\x42\x10\x4d\x8b\x4a\x18\x49\x2b\xe7\xe9"
        "\x96\x00\x00\x00\x44\x8b\x15\xb9\x00\x00"
        "\x00\x49\x8b\x0a\x4d\x8b\x42\x10\x4d\x8b"
        "\x4a\x18\x44\x8b\x25\xab\x00\x00\x00\x8b"
        "\x05\xa5\x00\x00\x00\x83\xe8\x04\x49\xc7"
        "\xc6\x02\x00\x00\x00\x48\x33\xd2\x49\xf7"
        "\xf6\x85\xd2\x74\x1b\x8b\x05\x8b\x00\x00"
        "\x00\x83\xe8\x04\x49\xc7\xc6\x08\x00\x00"
        "\x00\x49\xf7\xe6\x83\xc0\x20\x48\x2b\xe0"
        "\xeb\x19\x8b\x05\x70\x00\x00\x00\x83\xe8"
        "\x04\x49\xc7\xc6\x08\x00\x00\x00\x49\xf7"
        "\xe6\x83\xc0\x28\x48\x2b\xe0\x49\x8b\x52"
        "\x08\x89\x05\x4b\x00\x00\x00\x49\x83\xec"
        "\x04\x49\xc7\xc3\x04\x00\x00\x00\x44\x8b"
        "\x35\x3d\x00\x00\x00\x4f\x8b\x14\xde\x4e"
        "\x89\x14\xdc\x49\xff\xc3\x49\xff\xcc\x4d"
        "\x85\xe4\x75\xe6\x41\xff\xd5\x8b\x0d\x1d"
        "\x00\x00\x00\x48\x03\xe1\x41\x5f\x41\x5e"
        "\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x8b\x0d"
        "\x04\x00\x00\x00\x48\x03\xe1\xcb\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00";

    inline std::unordered_map<char*, uint32_t> x64_functions = { { get_x64_peb_address_shellcode, sizeof(get_x64_peb_address_shellcode) - 1 },
        { x64_memcpy_shellcode, sizeof(x64_memcpy_shellcode) - 1 }, { get_string_shellcode, sizeof(get_string_shellcode) - 1 },
        { x64_api_call_shellcode, sizeof(x64_api_call_shellcode) - 1 }, { get_x64_teb_address_shellcode, sizeof(get_x64_teb_address_shellcode) - 1 } };
}

// 64 bit definitions of some required structures
namespace x64
{
    struct LDR_ENTRY
    {
        union
        {
            DEFINE_MEMBER_N(uint32_t, Flags, 0x68);
            DEFINE_MEMBER_N(uint16_t, ObsoleteLoadCount, 0x6C);
            DEFINE_MEMBER_N(LIST_ENTRY, HashLinks, 0x70);
        };
    };

    struct call
    {
        uint32_t number_of_args;
        void* arguments_array;
        uint64_t api_address;
    };

    struct UNICODE_STRING
    {
        USHORT Length;
        USHORT MaximumLength;
        uint64_t Buffer;
    };

    struct LIST_ENTRY
    {
        uint64_t Flink;
        uint64_t Blink;
    };

    struct LDR_DATA_TABLE_ENTRY
    {
        UINT64 Reserved1[2];
        LIST_ENTRY InMemoryOrderLinks;
        uint64_t Reserved2[2];
        uint64_t DllBase;
        uint64_t Reserved3[2];
        UNICODE_STRING FullDllName;
        BYTE Reserved4[8];
        uint64_t Reserved5[3];
#pragma warning(push)
#pragma warning(disable: 4201)
        union
        {
            ULONG CheckSum;
            uint64_t Reserved6;
        } DUMMYUNIONNAME;
#pragma warning(pop)
        ULONG TimeDateStamp;
    };

    struct MEMORY_BASIC_INFORMATION
    {
        UINT64 BaseAddress;
        UINT64 AllocationBase;
        DWORD AllocationProtect;
        WORD   PartitionId;
        UINT64 RegionSize;
        DWORD State;
        DWORD Protect;
        DWORD Type;
    };
};

namespace asm_fn
{
    extern "C" uint32_t get_x64_peb_address();

    // first arg is a pointer to pointer
    extern "C" void x64_memcpy(uint64_t* source, void* destination, uint32_t size);

    // first arg is a pointer to pointer
    extern "C" void get_string(uint64_t* source, void* destination);

    extern "C" uint32_t x64_api_call(x64::call* call_struct);
    extern "C" uint32_t get_x64_teb_address();
    extern "C" void x64_debug_break();
}

namespace x64
{
    template <typename arg>
    void expand(std::vector<uint64_t>& vec, arg argument)
    {
        vec.push_back(argument);
    }

    // I added it because narrowing conversion is illegal in initializer_list
    template<typename ...args, typename first>
    void expand(std::vector<uint64_t>& vec, first arg1, args... rest_args)
    {
        expand(vec, arg1);
        expand(vec, rest_args...);
    }

    template<typename ...args>
    uint32_t call_api(uint64_t fun_address, args... arguments)
    {
        call call_struct;
        std::vector<uint64_t> fun_args;
        expand(fun_args, arguments...);
        call_struct.api_address = fun_address;
        call_struct.number_of_args = fun_args.size();
        call_struct.arguments_array = fun_args.data();
        return asm_fn::x64_api_call(&call_struct);
    }
}

class parser
{
private:
    std::unordered_map<std::string, uint64_t> libraries;
    std::unordered_map<std::string, uint64_t> functions;
public:
    parser();
    uint64_t get_function_address(std::string fn_name);
    uint64_t get_library_address(std::string library_name);
    uint64_t parse_dll_in_ldr_table(const std::wstring& dll_name);
    uint64_t parse_ldr_entry(const std::wstring& dll_name);
    uint64_t find_entry(uint64_t ldr, uint64_t list_flink, const std::wstring& dll_name, uint64_t custom_offset = 0);
    uint64_t get_first_ldr_entry(uint32_t index = 0);
    std::vector<std::pair<std::string, uint64_t>> find_export_in_dll(uint64_t base_address, const std::vector<std::string>& functions);
};