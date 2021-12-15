// source code of RtlEqualUnicodeStringHook shellcode
#include <Windows.h>
#include <winternl.h>
#include <stdint.h>

BOOLEAN(*OrigUnicodeStringCmp)(PUNICODE_STRING string1, PUNICODE_STRING string2, BOOLEAN case_in_sensitive);

BOOLEAN RtlEqualUnicodeStringHook(PUNICODE_STRING string1, PUNICODE_STRING string2, BOOLEAN case_insensitive)
{
  wchar_t buff[] = L"KERNEL32.DLL";
  constexpr uint16_t buff_size = 0x18;
  if (string1->Length == buff_size && string2->Length == buff_size && case_insensitive)
  {
    for (int j = 0; j < 12; j++)
    {
      if (string1->Buffer[j] != buff[j])
      {
        return OrigUnicodeStringCmp(string1, string2, case_insensitive);
      }
    }

    for (int j = 0; j < 12; j++)
    {
      if (string2->Buffer[j] != buff[j])
      {
        return OrigUnicodeStringCmp(string1, string2, case_insensitive);
      }
    }

    return false;
  }

  return OrigUnicodeStringCmp(string1, string2, case_insensitive);
}
