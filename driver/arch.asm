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
	push 1					; push some dummy data onto the stack which will exist in writeback cache
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

END