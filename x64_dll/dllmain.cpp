#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <iostream>
#include <winternl.h>
#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

/*
    You can't use most of the exported functions from kernel32.dll
    and kernelbase.dll but you can freely use the ntdll.dll export.
*/
uint64_t parse_function_from_ntdll(std::string_view function_name)
{
  static void* ntdll_base = nullptr;

  if (ntdll_base == nullptr)
  {
    auto peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    auto ldr = peb->Ldr;
    auto ldr_entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(ldr->Reserved2[1]);
    auto temp = ldr_entry;

    do
    {
      if (StrStrIW(ldr_entry->FullDllName.Buffer, L"ntdll.dll"))
      {
        ntdll_base = ldr_entry->DllBase;
        break;
      }

      ldr_entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(ldr_entry->Reserved1[0]);

    } while (ldr_entry != temp);
  }

  const auto base_as_number = reinterpret_cast<uint64_t>(ntdll_base);
  const auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(ntdll_base);
  const auto nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(base_as_number + dos_header->e_lfanew);

  const auto export_table = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base_as_number + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  const auto name_table = reinterpret_cast<uint32_t*>(export_table->AddressOfNames + base_as_number);
  const auto ordinal_table = reinterpret_cast<uint16_t*>(export_table->AddressOfNameOrdinals + base_as_number);
  const auto function_table = reinterpret_cast<uint32_t*>(export_table->AddressOfFunctions + base_as_number);

  for (int j = 0; j < export_table->NumberOfNames; j++)
  {
    std::string_view current_function = reinterpret_cast<char*>(name_table[j] + base_as_number);
    if (StrStrIA(current_function.data(), function_name.data()))
    {
      auto ord = ordinal_table[j];
      return function_table[ord] + base_as_number;
    }
  }

  return NULL;
}

__declspec(dllexport) bool test_function()
{
  auto result = parse_function_from_ntdll("LdrLoadDll");
  std::cout << "Hello from long mode, result is 0x" << std::hex << result << "\n";
  return true;
}

BOOL APIENTRY DllMain(HMODULE hModule,
  DWORD  ul_reason_for_call,
  LPVOID lpReserved
)
{
  switch (ul_reason_for_call)
  {
  case DLL_PROCESS_ATTACH:
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH:
    break;
  }

  return TRUE;
}

