.macro push_all
    pushq    %rax
    pushq    %rbx
    pushq    %rcx
    pushq    %rdx
    pushq    %rbp
    pushq    %rsi
    pushq    %rdi
    pushq    %r8
    pushq    %r9
    pushq    %r10
    pushq    %r11
    pushq    %r12
    pushq    %r13
    pushq    %r14
    pushq    %r15
.endm

.macro pop_add
    popq     %r15
    popq     %r14
    popq     %r13
    popq     %r12
    popq     %r11
    popq     %r10
    popq     %r9
    popq     %r8
    popq     %rdi
    popq     %rsi
    popq     %rbp
    popq     %rdx
    popq     %rcx
    popq     %rbx
    popq     %rax
.endm


.data
.globl _hook_linux_x64_getStaticLicense_target
_hook_linux_x64_getStaticLicense_target:
.quad 0
.globl _hook_linux_x64_injected_target
_hook_linux_x64_injected_target:
.quad 0
.globl _hook_linux_x64_getaddrinfo_target
_hook_linux_x64_getaddrinfo_target:
.quad 0

.text
.globl	_hook_linux_x64_getStaticLicense
.globl	_hook_linux_x64_injected
.globl	_hook_linux_x64_getaddrinfo


_hook_linux_x64_getStaticLicense:
push %rdi
push %rdx
movabs $_hook_linux_x64_getStaticLicense_target@GOTOFF, %rdi
lea _GLOBAL_OFFSET_TABLE_(%rip), %rdx
add %rdx, %rdi
movq (%rdi), %rdi
movq %rdi, %rax
pop %rdx
pop %rdi
call %rax
ret


#TODO!
_hook_linux_x64_injected:
push %rdi
push %rdx
movabs $_hook_linux_x64_injected_target@GOTOFF, %rdi
lea _GLOBAL_OFFSET_TABLE_(%rip), %rdx
add %rdx, %rdi
movq (%rdi), %rdi
movq %rdi, %rax
pop %rdx
pop %rdi
movq %r13, %rdi
call %rax
nop
nop
nop
nop
ret

_hook_linux_x64_getaddrinfo:
push %rdi
push %rdx
movabs $_hook_linux_x64_getaddrinfo_target@GOTOFF, %rdi
lea _GLOBAL_OFFSET_TABLE_(%rip), %rdx
add %rdx, %rdi
movq (%rdi), %rdi
movq %rdi, %rax
pop %rdx
pop %rdi
call %rax
ret