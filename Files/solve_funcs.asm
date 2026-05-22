;	This technique is the hell's Gate 
;
;	It will be use for Call invocation
;
;	Hope work

	option	casemap:none

.data 
	CallValue DWORD 000h

.code 

ALIGN 16

	asm_func PROC PUBLIC
		ret
	asm_func ENDP

	SetCall PROC 
		mov CallValue, 000h
		mov CallValue, ecx
		ret
	SetCall ENDP

	CallFunc PROC 
		mov r10, rcx
		mov eax, CallValue

		syscall
		ret
	CallFunc ENDP

end