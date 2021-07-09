.model flat, c

.data

extern get_x64_teb_address_shellcode:DWORD
extern get_x64_peb_address_shellcode:DWORD
extern x64_memcpy_shellcode:DWORD
extern get_string_shellcode:DWORD
extern x64_api_call_shellcode:DWORD

call_to_x64 dd ?
x64_segment dw 33h ; x64 code segment selector

.code

get_x64_peb_address proc
	lea eax, get_x64_peb_address_shellcode
	mov dword ptr [call_to_x64], eax
	mov eax, offset call_to_x64 ; setup address to x64 code
	switch_call_0 db 0ffh, 018h ; call fword [eax]
	ret
get_x64_peb_address endp

x64_memcpy proc ; esp + 4: ptr to source address, esp + 8: destination address, esp + 12: size in bytes to copy
	lea eax, x64_memcpy_shellcode
	mov dword ptr [call_to_x64], eax
	mov eax, offset call_to_x64 ; setup address to x64 code
	switch_call_1 db 0ffh, 018h ; call fword [eax]
	ret
x64_memcpy endp

get_string proc ; esp + 4: ptr to source address, esp + 8: destination address
	lea eax, get_string_shellcode
	mov dword ptr [call_to_x64], eax
	mov eax, offset call_to_x64 ; setup address to x64 code
	switch_call_2 db 0ffh, 018h ; call fword [eax]
	ret
get_string endp

x64_api_call proc
	lea eax, dword ptr x64_api_call_shellcode
	mov dword ptr [call_to_x64], eax
	mov eax, offset call_to_x64 ; setup address to x64 code

	mov ecx, dword ptr [esp+4]
	mov edx, dword ptr [ecx+4] ; ptr to array with args
	mov ecx, dword ptr [ecx] ; number of args

	switch_call_3 db 0ffh, 018h ; call fword [eax]
	ret
x64_api_call endp

get_x64_teb_address proc
	lea eax, get_x64_teb_address_shellcode
	mov dword ptr [call_to_x64], eax
	mov eax, offset call_to_x64 ; setup address to x64 code
	switch_call_4 db 0ffh, 018h ; call fword [eax]
	ret
get_x64_teb_address endp

x64_debug_break proc
	mov eax, x64
	mov dword ptr [call_to_x64], eax
	mov eax, offset call_to_x64 ; setup address to x64 code
	switch_call_5 db 0ffh, 018h ; call fword [eax]
	ret
	x64:
	break db 0cch ; int 3
	retf
x64_debug_break endp

end