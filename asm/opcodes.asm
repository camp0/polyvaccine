section .data
msg:    db 'Hola\n'
section .text
global _start
indireciones:
	mov eax,[esi]
	mov ebx,[esi]
	mov ecx,[esi]
	mov edx,[esi]

	mov rax,[rsi]
	mov rbx,[rsi]
	mov rcx,[rsi]
	mov rdx,[rsi]

	ret	
	mov edx,[edi]
	mov ebx,[edi]
	mov ecx,[edi]
	mov edx,[edi]
	
	mov eax,[edi + 2]
	mov ebx,[edi + 8]
	mov ecx,[edi + 16]
	mov edx,[edi + 32]
	
	mov eax,[esp]
	mov ebx,[esp]
	mov ecx,[esp]
	mov edx,[esp]
	
	mov eax,[ebx]
	mov ebx,[ebx]
	mov ecx,[ebx]
	mov edx,[ebx]

	mov eax,[eax]
	mov ebx,[eax]
	mov ecx,[eax]
	mov edx,[eax]

	mov eax,[ecx]
	mov ebx,[ecx]
	mov ecx,[ecx]
	mov edx,[ecx]
	
	mov eax,[edx]
	mov ebx,[edx]
	mov ecx,[edx]
	mov edx,[edx]
 	mov eax,[ebx+1]
 	mov ebx,[ebx+1]
 	mov ecx,[ebx+1]
 	mov edx,[ebx+1]
 
 	mov eax,[eax+2]
 	mov ebx,[eax+2]
 	mov ecx,[eax+2]
 	mov edx,[eax+2]
 
 	mov eax,[ecx+1]
 	mov ebx,[ecx+2]
 	mov ecx,[ecx+3]
 	mov edx,[ecx+4]

	mov eax,[ebp + ecx]
	mov ebx,[ebp + ecx] 
	mov ecx,[ebp + ecx]
	mov edx,[ebp + ecx]
	mov edx,[ebp + ecx + 2] 
        mov [ebp + ecx],ecx
mas1:
	mov eax,[esp + ecx]
	mov [esp + ecx],eax
	mov ebx,[esp + ecx] 
	mov ecx,[esp + ecx]
	mov edx,[esp + ecx]
	mov edx,[esp + ecx + 2] 
        mov [esp + ecx],ecx
mas6:	
	mov eax,[esi + ecx]
	mov [esi + ecx],eax
	mov ebx,[esi + ecx] 
	mov ecx,[esi + ecx]
	mov edx,[esi + ecx]
	mov edx,[esi + ecx + 2] 


mas2:
	mov eax,[edx + ecx]
	mov [edx + ecx],eax
	mov ebx,[edx + ecx] 
	mov ecx,[edx + ecx]
	mov edx,[edx + ecx]
	mov edx,[edx + ecx + 2] 
        mov [edx + ecx],ecx

blabla:
        mov [eax],ebx
        mov [ebx],ebx
        mov [ecx],ebx
        mov [edx],ebx

        mov [eax],eax
        mov [ebx],eax
        mov [ecx],eax
        mov [edx],eax

        mov [eax],ecx
        mov [ebx],ecx
        mov [ecx],ecx
        mov [edx],ecx

        mov [eax],edx
        mov [ebx],edx
        mov [ecx],edx
        mov [edx],edx

movidas:
        xor [eax],ebx
        add [ebx],ebx
        cmp [ecx],ebx
        sub [edx],ebx

        xor [eax+12],ebx
        xor [eax+1],ebx
        xor [eax+2],ebx
        add [ebx + ecx ],ebx
        cmp [ecx + 0],ebx
        sub ebx,[ecx]
        xor [ebx+12],ebx
        xor [ebx+1],ebx
        xor [ebx+2],ebx

        xor [ecx+12],edx
        xor [ecx+1],edx
        xor [ecx+2],esp
et1: 
        xor [edx+12],edx
        xor [edx+1],edx
        xor [edx+2],esp
        xor [edx+2],ebp

        add [eax],ecx
        add eax,[ecx]

        sub [eax],ecx
        sub eax,[ecx]

        sub eax,0x11
        sub rax,0x11

        sub [rax],rcx
        sub rax,[rcx]

        adc [eax],ecx
        adc eax,[ecx]
        and [eax],ecx
        and eax,[ecx]

        xchg [eax],ecx
        xchg eax,[ecx]
        sbb [eax],ecx
        sbb eax,[ecx]

;       aas [eax],ecx
;       aas eax,[ecx]
;       aaa [eax],ecx
;       aaa eax,[ecx]

;       das [eax]
;       das eax
;       das [eax],ecx
;       das eax,[ecx]
;       inc [eax]
;       inc [ecx]
;       mul eax,[ecx]
;       imul [eax],ecx
        imul eax,[ecx]

;       div [eax],ecx
;       div eax,[ecx]

        or [eax],ecx
        or eax,[ecx]
        xor [eax],ecx
        xor eax,[ecx]


masmovi:
       ; xchg [eax],[esp]
;	pop [ebp]
;	push [ecx]
;        add [ebx],[edx]
;        mov [ecx],[edx]
;        mov [edx],[edx]
leches:
	nop
;	pop ecx
	mov ebx,$8
	mov eax,$1
	int 0x80	

print:
	mov ecx,$msg
        mov edx,$6
        mov ebx,$1
        mov eax,$4
        int 0x80
	ret

_start:
	call $print
	call $sig
	;call 0x00000004 
sig:
	;call $print
	add ecx,8
	jmp $otro 
	mov ebx,$0
	mov eax,$1
	int 0x80
otro:	mov ebx,$1
	mov eax,$1
	int 0x80

	hlt
	mov ebx,$2
	mov eax,$1
	int 0x80

