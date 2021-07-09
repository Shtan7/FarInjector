; here are the source codes of the shellcodes located in the x64_shellcode namespace from the "dll_related_things.hpp" file

get_teb proc
	mov rax, qword ptr gs:[30h]
	retf
get_teb endp

call_api proc ; perform call of 64 bit api with fastcall
	mov dword ptr [array_ptr], edx
	mov dword ptr [number_of_args], ecx
	mov rax, rsp
	and rax, 0Fh
	cmp rax, 0
	je stack_ok
	sub rsp, rax

	stack_ok:
	mov dword ptr [stack_alignment], eax
	push r10 ; temp
	push r11 ; counter
	push r12 ; number of args
	push r13 ; api address
	push r14 ; divider, multiplier
	push r15 ; stack decrease

	mov r13d, dword ptr [rsp+60+rax]
	mov r13, qword ptr [r13+8]
	mov r15, 28h
	mov dword ptr [stack_reduction], r15d

	test rcx, rcx
	jz zero_args
	cmp rcx, 1
	je arg_0
	cmp rcx, 2
	je arg_1
	cmp rcx, 3
	je arg_2
	cmp rcx, 4
	je arg_3
	jg more_args

	zero_args:
	sub rsp, r15
	jmp function_call

	arg_0:
	mov r10d, dword ptr [array_ptr]
	mov rcx, qword ptr [r10]
	sub rsp, r15
	jmp function_call

	arg_1:
	mov r10d, dword ptr [array_ptr]
	mov rcx, qword ptr [r10]
	mov rdx, qword ptr [r10+8]
	sub rsp, r15
	jmp function_call

	arg_2:
	mov r10d, dword ptr [array_ptr]
	mov rcx, qword ptr [r10]
	mov rdx, qword ptr [r10+8]
	mov r8, qword ptr [r10+16]
	sub rsp, r15
	jmp function_call

	arg_3:
	mov r10d, dword ptr [array_ptr]
	mov rcx, qword ptr [r10]
	mov rdx, qword ptr [r10+8]
	mov r8, qword ptr [r10+16]
	mov r9, qword ptr [r10+24]
	sub rsp, r15
	jmp function_call

	more_args:
	mov r10d, dword ptr [array_ptr]
	mov rcx, qword ptr [r10]
	mov r8, qword ptr [r10+16]
	mov r9, qword ptr [r10+24]
	mov r12d, dword ptr [number_of_args]
	mov eax, dword ptr [number_of_args]
	sub eax, 4
	mov r14, 2
	xor rdx, rdx ; clear before div
	div r14
	test edx, edx ; check alignment
	jz second_variant

	first_variant:
	mov eax, dword ptr [number_of_args]
	sub eax, 4
	mov r14, 8
	mul r14
	add eax, 20h
	sub rsp, rax
	jmp args_unpacking

	second_variant:
	mov eax, dword ptr [number_of_args]
	sub eax, 4
	mov r14, 8
	mul r14
	add eax, 28h
	sub rsp, rax

	args_unpacking:
	mov rdx, qword ptr [r10+8]
	mov dword ptr [stack_reduction], eax
	sub r12, 4 ; left number of args in array
	mov r11, 4 ; index in args array

	loop_label:
	mov r14d, dword ptr [array_ptr]
	mov r10, qword ptr [r14+r11*8] ; load arg from array
	mov qword ptr [rsp+r11*8], r10 ; push it to stack
	inc r11
	dec r12
	test r12, r12
	jnz loop_label

	function_call:
	call r13

	epilog:
	mov ecx, dword ptr [stack_reduction]
	add rsp, rcx
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	mov ecx, dword ptr [stack_alignment]
	add rsp, rcx
	retf

	local_variables:
	stack_alignment dd 0
	stack_reduction dd 0
	array_ptr dd 0
	number_of_args dd 0
call_api endp

get_peb proc
	mov rax, qword ptr gs:[60h]
	retf
get_peb endp

memcpy proc
	mov ecx, dword ptr [rsp+12] ; ptr to source address
	mov r8, qword ptr [rcx] ; extract source address
	mov edx, dword ptr [rsp+16] ; destination address
	mov ecx, dword ptr [rsp+20] ; size in bytes

	push rdi
	push rsi

	mov rsi, r8
	mov rdi, rdx
	rep movsb

	pop rsi
	pop rdi
	retf
memcpy endp

get_string proc ; read array until zero is met
	xor rax, rax
	mov ecx, dword ptr [rsp+12]
	mov r8, qword ptr [rcx] ; source address
	mov r9d, dword ptr [rsp+16] ; destination address

	push rdi
	push rsi
	mov rsi, r8
	mov rdi, r8
	mov rcx, -1

	repne scasb
	not rcx

	mov rdi, r9
	rep movsb
	
	pop rsi
	pop rdi
	retf
get_string endp