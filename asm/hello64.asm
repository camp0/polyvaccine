;;Compile and link with,
;;;;;$> nasm -felf64 hello.asm
;;;;;$> ld -s -o hello hello.o
%define __NR_write  1
%define __NR_exit   60
%define STDOUT  1
section .data

message:
    db      'hello, world!', 10, 0
    msglen equ $-message

section .text

global _start
_start:
    xor     rax,rax
    xor     rbx,rbx
    xor     rcx,rcx
    xor     rdx,rdx
    jmp     pepe 
pepe:    mov     rax, __NR_write   ;;;write(STDOUT,message,msglen);
    mov     rdi, STDOUT
    mov     rsi, message
    mov     rdx, msglen 
    syscall

    mov     rax, __NR_exit    ;;exit(0);
    xor     rdi, rdi
    syscall
