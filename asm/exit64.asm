;;Compile and link with,
;;;;;$> nasm -felf64 hello.asm
;;;;;$> ld -s -o hello hello.o
%define __NR_exit   60
section .text

global _start
_start:
    nop
    nop
	jmp pepe
	ret
pepe:    mov     rbx, 0x1
    mov     rax, __NR_exit    ;;exit(0);
    mov     rdi,1 
    ;xor     rdi, rdi
    syscall
