; This is NASM!
; mov <dest>, <src>
; Initialized data
.data
_hook_windows_x64_getaddrinfo_target dq 0
_hook_windows_x64_getaddrinfo_jump dq 0

_hook_windows_x64_injected_target dq 0
_hook_windows_x64_injected_jump dq 0

_hook_windows_x64_getlicenseroot_target dq 0
_hook_windows_x64_getlicenseroot_1_jump dq 0
_hook_windows_x64_getlicenseroot_2_jump dq 0

_hook_windows_x64_dns_send_target dq 0
_hook_windows_x64_dns_send_jump dq 0

.code
PUBLIC _hook_windows_x64_getaddrinfo
PUBLIC _hook_windows_x64_getaddrinfo_target
PUBLIC _hook_windows_x64_getaddrinfo_jump

PUBLIC _hook_windows_x64_injected_316
PUBLIC _hook_windows_x64_injected_317
PUBLIC _hook_windows_x64_injected_target
PUBLIC _hook_windows_x64_injected_jump

PUBLIC _hook_windows_x64_getlicenseroot_1_316
PUBLIC _hook_windows_x64_getlicenseroot_2_316
PUBLIC _hook_windows_x64_getlicenseroot_1_317
PUBLIC _hook_windows_x64_getlicenseroot_2_317

PUBLIC _hook_windows_x64_getlicenseroot_target
PUBLIC _hook_windows_x64_getlicenseroot_1_jump
PUBLIC _hook_windows_x64_getlicenseroot_2_jump

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
    lea     r9, [rsi+180h] ;13FCC3DD5
    lea     r8, [rsi+48h] ;13FCC3DDC
    mov     rdx, rdi ;13FCC3DE0
    mov     rcx, rbx ;13FCC3DE3

    sub rsp, 20h
    lea rax, _hook_windows_x64_getaddrinfo_target
    mov rax, [rax]
    call rax                                         ;If we call here again it gives us (unknown why) a undefined behavior
    add rsp, 20h

    lea rdx, _hook_windows_x64_getaddrinfo_jump
    mov rdx, [rdx]
    jmp rdx

_hook_windows_x64_injected_316:
    mov rcx, rsi
    jmp _hook_windows_x64_injected

_hook_windows_x64_injected_317:
    mov rcx, r14

_hook_windows_x64_injected:
    pushaq
    sub rsp, 20h
    lea rax, _hook_windows_x64_injected_target
    mov rax, [rax]
    call rax
    add rsp, 20h
    popaq

    ;We have to jump back again :)
    lea rax, _hook_windows_x64_injected_jump
    mov rax, [rax]
    jmp rax

;\x4C\x8B\x44\x24\x00\x4D\x2B\xC8\x48\x89\xBC\x24\x00\x00\x00\x00\x48\x8B\x15\x00\x00\x00\x00\x48\x8D\x8C\x24\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x90, xxxx?xxxxxxx????xxx????xxxx????x????x
;0x01404E7E43 - 0x1404E7E5A
_hook_windows_x64_getlicenseroot_1_316:
    mov     r8, qword ptr [rsp+58h]
    sub     r9, r8
    mov     [rsp+0C0h], rdi
    pushaq
    lea rax, _hook_windows_x64_getlicenseroot_target
    mov rax, [rax]
    call rax
    popaq
    mov rdx, rax

    ;We have to jump back again :)
    lea rax, _hook_windows_x64_getlicenseroot_1_jump
    mov rax, [rax]
    jmp rax

;\x48\x89\xBC\x24\x00\x00\x00\x00\x4C\x8D\x44\x24\x00\x48\x8B\x15\x00\x00\x00\x00\x48\x8B\x9C\x24\x00\x00\x00\x00, xxxx????xxxx?xxx????xxxx????
;0x1404E7F51 - 0x1404E7F35
_hook_windows_x64_getlicenseroot_2_316:
    mov [rsp + 88h], rdi
    lea r8, [rsp + 78h]
    pushaq
    lea rax, _hook_windows_x64_getlicenseroot_target
    mov rax, [rax]
    call rax
    popaq
    mov rdx, rax

    ;We have to jump back again :)
    lea rax, _hook_windows_x64_getlicenseroot_2_jump
    mov rax, [rax]
    jmp rax

_hook_windows_x64_getlicenseroot_1_317:
    sub     r9, r8
    mov     [rsp+1A18h - 01968h], rdi
    pushaq
    lea rax, _hook_windows_x64_getlicenseroot_target
    mov rax, [rax]
    call rax
    popaq
    mov rdx, rax

    ;We have to jump back again :)
    lea rax, _hook_windows_x64_getlicenseroot_1_jump
    mov rax, [rax]
    jmp rax

_hook_windows_x64_getlicenseroot_2_317:
    lea r8, [rsp + 1A18h - 19A0h]
    mov rbx, [rsp + 1A18h - 01968h]
    pushaq
    lea rax, _hook_windows_x64_getlicenseroot_target
    mov rax, [rax]
    call rax
    popaq
    mov rdx, rax

    ;We have to jump back again :)
    lea rax, _hook_windows_x64_getlicenseroot_2_jump
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
END