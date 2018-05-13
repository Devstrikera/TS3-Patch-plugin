#.cstring
#Not realy needed
#    LC0:
#    .ascii "Hello World\0"
.text
.globl __main
__main:
nop
popq %rax
call %rax
ret