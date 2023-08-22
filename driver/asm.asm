.code


; Tests the emulation of the INVD instruction
;
; source and references:
;
; https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html#invdwbinvd
; https://www.felixcloutier.com/x86/invd
; https://www.felixcloutier.com/x86/wbinvd
;
; Returns int

TestINVDEmulation PROC

	pushfq
	cli
	push 1					; push some dummy data onto the stack which will exist in writeback memory
	wbinvd					; flush the internal cpu caches and write back all modified cache 
							; lines to main memory
	mov byte ptr [rsp], 0	; set our dummy value to 0, this takes place inside writeback memory
	invd					; flush the internal caches, however this instruction will not write 
							; back to system memory as opposed to wbinvd, meaning our previous 
							; instruction which only operated on cached writeback data and not
							; system memory has been invalidated. 
	pop rax					; on a real system as a result of our data update instruction being
							; invalidated, the result will be 1. On a system that does not
							; properly implement INVD, the result will be 0 as the instruction does
							; not properly flush the caches.
	xor rax, 1				; invert result so function returns same way as all verification methods
	popfq
	ret

TestINVDEmulation ENDP


;
; Note: fild and fistp respectively are used for loading and storing integers in the FPU,
; while fld and fstp are used for floating point numbers. No need to use xmm registers
; as we dont need that level of precision and we need to be as efficient as possible
;
; compiler will take care of saving the SSE state for us and restoring it source:
; https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-floating-point-or-mmx-in-a-wdm-driver
;
; arguments: INT64 in RCX
; returns resulting number lol

MySqrt PROC

	push rbp
	mov rbp, rsp
	sub rsp, 16
	mov [rsp + 8], rcx			; cannot directly move from a register into a fp register
	fild qword ptr[rsp + 8]		; push our number onto the FPU stack
	fsqrt  						; perform the square root
	fistp qword ptr[rsp]		; pop the value from the floating point stack into our general purpose stack
	mov rax, qword ptr[rsp]		; store value in rax for return
	add rsp, 16
	pop rbp
	ret

MySqrt ENDP

END