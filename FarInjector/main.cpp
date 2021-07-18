#include "dll_related_things.hpp"
#include <iostream>
#include <winternl.h>

/*
	Without hook at RtlEqualUnicodeString we can't load
	kernel32.dll because the internal check denies loading of
	"known" dlls.
*/
bool hook_RtlEqualUnicodeString(std::shared_ptr<parser> parser_obj)
{
	NTSTATUS status;
	uint64_t ptr_to_orig_function;
	uint64_t change_permissions = parser_obj->get_function_address("RtlEqualUnicodeString");
	uint64_t address_to_hook = parser_obj->get_function_address("RtlEqualUnicodeString");
	uint64_t bytes_to_protect = 0x1000;
	uint32_t old_protection;
	uint64_t tramp_address = 0;

	status = x64::call_api(parser_obj->get_function_address("NtProtectVirtualMemory"), (uint64_t)-1, reinterpret_cast<uint64_t>(&change_permissions),
		reinterpret_cast<uint64_t>(&bytes_to_protect), PAGE_EXECUTE_READWRITE, reinterpret_cast<uint64_t>(&old_protection));

	if (!NT_SUCCESS(status))
	{
		return false;
	}

	for (uint64_t addr = address_to_hook; addr > address_to_hook - 0x80000000; addr -= 0x1000)
	{
		status = x64::call_api(parser_obj->get_function_address("NtAllocateVirtualMemory"), (uint64_t)-1,
			reinterpret_cast<uint64_t>(&addr), 0, reinterpret_cast<uint64_t>(&bytes_to_protect), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (NT_SUCCESS(status))
		{
			tramp_address = addr;
			break;
		}
	}

	if (!tramp_address)
	{
		return false;
	}

	uint8_t trampoline[] = { "\x48\x89\x5c\x24\x08""\xE9\x00\x00\x00\x00" };
	int jmp_rel_from_trampoline = address_to_hook - tramp_address - 10 + 5;
	memcpy(trampoline + 6, &jmp_rel_from_trampoline, sizeof(jmp_rel_from_trampoline));

	status = x64::call_api(parser_obj->get_function_address("NtWriteVirtualMemory"), (uint64_t)-1, tramp_address,
		reinterpret_cast<uint64_t>(trampoline), sizeof(trampoline) - 1, NULL);

	if (!NT_SUCCESS(status))
	{
		return false;
	}

	status = x64::call_api(parser_obj->get_function_address("NtWriteVirtualMemory"), (uint64_t)-1, tramp_address + 10,
		reinterpret_cast<uint64_t>(x64_shellcode::RtlEqualUnicodeStringHook), sizeof(x64_shellcode::RtlEqualUnicodeStringHook) - 1, NULL);

	if (!NT_SUCCESS(status))
	{
		return false;
	}

	uint8_t jmp_to_hook_function[] = { "\xE9\x00\x00\x00\x00" };
	int jmp_rel_to_trampoline = tramp_address - address_to_hook - 5 + 10;
	memcpy(jmp_to_hook_function + 1, &jmp_rel_to_trampoline, sizeof(jmp_rel_to_trampoline));

	status = x64::call_api(parser_obj->get_function_address("NtWriteVirtualMemory"), (uint64_t)-1, address_to_hook,
		reinterpret_cast<uint64_t>(jmp_to_hook_function), sizeof(jmp_to_hook_function) - 1, NULL);

	if (!NT_SUCCESS(status))
	{
		return false;
	}

	ptr_to_orig_function = tramp_address + 191 + 10;
	uint64_t orig_function_address = tramp_address;

	status = x64::call_api(parser_obj->get_function_address("NtWriteVirtualMemory"), (uint64_t)-1, ptr_to_orig_function,
		reinterpret_cast<uint64_t>(&orig_function_address), sizeof(orig_function_address), NULL);

	if (!NT_SUCCESS(status))
	{
		return false;
	}

	return true;
}

int main()
{
	DWORD Dummy;
	for (auto& function : x64_shellcode::x64_functions)
	{
		if (!VirtualProtect(function.first, function.second, PAGE_EXECUTE_READWRITE, &Dummy))
		{
			std::cout << "Cannot change page permissions\n";
			return -1;
		}
	}

	std::shared_ptr<parser> parser_obj;

	try
	{
		parser_obj = std::make_shared<parser>();
	}
	catch (std::exception& e)
	{
		std::cout << e.what();
		return -1;
	}

	if (!hook_RtlEqualUnicodeString(parser_obj))
	{
		std::cout << "Cannot hook RtlEqualUnicodeString\n";
		return -1;
	}

	uint64_t output_address;
	x64::UNICODE_STRING kernel32_nt;
	kernel32_nt.Buffer = reinterpret_cast<uint64_t>(L"KERNEL32.DLL");
	kernel32_nt.Length = 0x18;
	kernel32_nt.MaximumLength = 0x1a;

	if (!NT_SUCCESS(x64::call_api(parser_obj->get_function_address("LdrLoadDll"), 0, 0, reinterpret_cast<uint64_t>(&kernel32_nt), reinterpret_cast<uint64_t>(&output_address))))
	{
		std::cout << "Cannot load kernel32.dll\n";
		return -1;
	}

	uint64_t base_address = parser_obj->parse_dll_in_ldr_table(L"KERNELBASE.dll");
	auto func_addr = parser_obj->find_export_in_dll(base_address, { {"LoadLibraryA"} });

	std::string_view test_dll = "x64_dll.dll";
	x64::call_api(func_addr[0].second, reinterpret_cast<uint64_t>(test_dll.data()));

	base_address = parser_obj->parse_dll_in_ldr_table(L"x64_dll.dll");
	func_addr = parser_obj->find_export_in_dll(base_address, { {"test_function"} });

	x64::call_api(func_addr.begin()->second, 0);

	system("pause");
	return 0;
}