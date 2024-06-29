bits 64
section .text
global start

start:
	sub rsp, 0x30					; clears some stack space for the function
	
	; BOOLEAN Result = SetHandleInformation()
	
	mov r8d, 1						; HANDLE_FLAG_INHERIT
	mov rdx, 1						; HANDLE_FLAG_INHERIT
	mov rcx, 0xAAAAAAAAAAAAAAAA 	; the handle value
	mov rax, 0xAAAAAAAAAAAAAAAA 	; SetHandleInformation
	call rax						; calls SetHandleInformation
	
	; sets the byte to be checked by the program
	
	mov rcx, 0xAAAAAAAAAAAAAAAA		; the address of the byte to set
	mov byte [rcx], al				; sets the byte
	
	add rsp, 0x30					; restores our stack
	xor rax, rax					; sets rax to zero
	ret								; returns
	nop								; the byte to set