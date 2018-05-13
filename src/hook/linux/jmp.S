# This is GAS/AT&T!
# mov <src>,<dest>
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