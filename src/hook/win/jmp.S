; This is NASM!
; mov <dest>, <src>
; Initialized data
.data
_hook_windows_x64_getaddrinfo_target dq 0
_hook_windows_x64_getaddrinfo_jump dq 0

_hook_windows_x64_injected_target dq 0
_hook_windows_x64_injected_jump dq 0

_hook_windows_x64_getlicenseroot_target dq 0
_hook_windows_x64_getlicenseroot_jump dq 0
_hook_windows_x64_getlicenseroot1_jump dq 0

_hook_windows_x64_dns_send_target dq 0
_hook_windows_x64_dns_send_jump dq 0

.code
PUBLIC _hook_windows_x64_getaddrinfo
PUBLIC _hook_windows_x64_getaddrinfo_target
PUBLIC _hook_windows_x64_getaddrinfo_jump

PUBLIC _hook_windows_x64_injected
PUBLIC _hook_windows_x64_injected_target
PUBLIC _hook_windows_x64_injected_jump

PUBLIC _hook_windows_x64_getlicenseroot
PUBLIC _hook_windows_x64_getlicenseroot_target
PUBLIC _hook_windows_x64_getlicenseroot_jump

PUBLIC _hook_windows_x64_getlicenseroot1
PUBLIC _hook_windows_x64_getlicenseroot1_jump

PUBLIC _hook_windows_x64_dns_send
PUBLIC _hook_windows_x64_dns_send_target
PUBLIC _hook_windows_x64_dns_send_jump

pushaq macro
;	PUSH    rax
	PUSH    rbx
	PUSH    rcx
	PUSH    rdx
	PUSH    rbp
	PUSH    rsi
	PUSH    rdi
	PUSH    r8
	PUSH    r9
	PUSH    r10
	PUSH    r11
	PUSH    r12
	PUSH    r13
	PUSH    r14
	PUSH    r15
endm

popaq macro
	POP     r15
	POP     r14
	POP     r13
	POP     r12
	POP     r11
	POP     r10
	POP     r9
	POP     r8
	POP     rdi
	POP     rsi
	POP     rbp
	POP     rdx
	POP     rcx
	POP     rbx
;	POP     rax
endm

_hook_windows_x64_getaddrinfo:
    lea r9, [rsp+130h -0F8h]                   ; F8 = ppResult |  - 08h -> we run into a call!
    lea r8, [rbp+57h - 0C8h]                   ; C8 = pHints |  - 08h -> we run into a call!
    xor edx, edx                               ; pServiceName



    sub rsp, 20h
    lea rax, _hook_windows_x64_getaddrinfo_target
    mov rax, [rax]
    call rax                                         ;If we call here again it gives us (unknown why) a undefined behavior
    add rsp, 20h

    lea rdx, _hook_windows_x64_getaddrinfo_jump
    mov rdx, [rdx]
    jmp rdx

_hook_windows_x64_injected:
    pushaq
    mov rcx, r14
    lea rax, _hook_windows_x64_injected_target
    mov rax, [rax]
    call rax
    popaq

    ;We have to jump back again :)
    lea rax, _hook_windows_x64_injected_jump
    mov rax, [rax]
    jmp rax

_hook_windows_x64_getlicenseroot:
    sub     r9, r8
    mov     [rsp+1A18h - 01968h], rdi

    ;for some reason, windows modyfies the register ...
    ;for safty reasons we just push & pop all
    pushaq
    lea rax, _hook_windows_x64_getlicenseroot_target
    mov rax, [rax]
    call rax
    popaq
    mov rdx, rax

    ;We have to jump back again :)
    lea rax, _hook_windows_x64_getlicenseroot_jump
    mov rax, [rax]
    jmp rax

_hook_windows_x64_getlicenseroot1:
    lea r8, [rsp + 1A18h - 19A0h] ;db 4Ch 8Dh 44h 24h 78h
    mov rbx, [rsp + 1A18h - 01968h] ;db 48h 8Bh 9Ch 24h 0B0h 00h 00h 00h

    ;for some reason, windows modyfies the register RCX, RDX, R8, R9,R10, R11
    ;for safty reasons we just push & pop all
    pushaq
    lea rax, _hook_windows_x64_getlicenseroot_target
    mov rax, [rax]
    call rax
    popaq
    mov rdx, rax

    ;We have to jump back again :)
    lea rax, _hook_windows_x64_getlicenseroot1_jump
    mov rax, [rax]
    jmp rax

_hook_windows_x64_dns_send:
    mov     rdx, [rdi+80h]
    mov     rcx, [rsi+20h]
    pushaq
    ;push rdi
    sub rsp, 20h
    ;mov     rdi, rsp
    ;mov ecx, 8
    ;mov eax, 0DDDDDDDDh
    ;rep stosd
    lea rax, _hook_windows_x64_dns_send_target
    mov rax, [rax]
    call rax
    add rsp, 20h
    ;pop rdi
    popaq
    ;ret

    ;We have to jump back again :)
    lea rcx, _hook_windows_x64_dns_send_jump
    mov rcx, [rcx]
    jmp rcx

test_function proc
    nop
    mov rax, 0AABBCCDDEEFFEEDDh
    call rax
    nop
    jmp rax
    nop
test_function endp

END