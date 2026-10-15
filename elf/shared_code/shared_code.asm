; Build commands:
;   nasm -f elf32 shared_code.asm -o shared_code.o
;   ld -m elf_i386 -o shared_code shared_code.o
;
; Every ENTRY is a function: it is the target of a `call` in _start (an STT_FUNC symbol). 
; Labels that are NOT entries are plain jump targets in the middle of another routine.
;
;   pair 1  p1_a        jnz into the MIDDLE of p1_prev (shared `ret`)
;                       and, when not taken, FALLS INTO the entry p1_b.
;
;   pair 2  p2_alt1/2   `mov ebx,n / test ebx,ebx / jnz p2_body`: alternate
;                       entries that join the body of p2_common. 
;                       The jnz is always taken, but a decoder sees a 
;                       conditional branch whose not-taken edge lands on the 
;                       entry p2_alt2.
;
;   pair 3  p3_y        jz BACK into the shared `ret` at the end of p3_x.
;
;   pair 4  p4_big_a/b  two entries of different routines that join one common
;                       multi-block body (with a loop): p4_big_a jumps over
;                       p4_big_b into it, p4_big_b reaches it with a jnz.
;
; The program is runnable: it calls every entry once and exits with status 0.

bits 32

section .data
var: dd 0

section .text
global _start:function

_start:
    call p1_prev
    call p1_a
    call p1_b
    call p2_common
    call p2_alt1
    call p2_alt2
    call p3_x
    call p3_y
    call p4_big_a
    call p4_big_b
    mov eax, 1              ; sys_exit
    xor ebx, ebx
    int 0x80

; ---------------------------------------------------------------- pair 1
global p1_prev:function
p1_prev:
    mov eax, [var]
    inc eax
    mov [var], eax
.shared_ret:                ; in the middle of p1_prev: p1_a jumps here
    ret

global p1_a:function
p1_a:
    mov eax, [var]
    test eax, eax
    jnz p1_prev.shared_ret  ; taken edge: into the middle of another function
                            ; not taken: falls into the entry p1_b
global p1_b:function
p1_b:
    mov dword [var], 1
    ret

; ---------------------------------------------------------------- pair 2
global p2_common:function
p2_common:
    xor ebx, ebx
p2_body:                    ; NOT an entry: where p2_alt1/p2_alt2 join
    mov eax, [var]
    test eax, eax
    jz .done
    add eax, ebx
    mov [var], eax
.done:
    ret

global p2_alt1:function
p2_alt1:
    mov ebx, 4
    test ebx, ebx           ; always non-zero: the jnz is always taken
    jnz p2_body

global p2_alt2:function
p2_alt2:                    ; p2_alt1's not-taken edge lands here
    mov ebx, 8
    test ebx, ebx
    jnz p2_body
    ret

; ---------------------------------------------------------------- pair 3
global p3_x:function
p3_x:
    mov eax, 1
    mov [var], eax
.shared_ret:                ; a 1-byte tail that p3_y also uses
    ret

global p3_y:function
p3_y:
    mov eax, [var]
    test eax, eax
    jz p3_x.shared_ret      ; back into another routine's last instruction
    dec eax
    mov [var], eax
    ret

; ---------------------------------------------------------------- pair 4
global p4_big_a:function
p4_big_a:
    mov ecx, [var]
    test ecx, ecx
    jz .out
    mov esi, 3
    jmp p4_body             ; over p4_big_b, into the common body
.out:
    ret

global p4_big_b:function
p4_big_b:
    mov esi, 5
    test esi, esi
    jnz p4_body
    ret

p4_body:                    ; NOT an entry: shared by p4_big_a and p4_big_b
    xor edi, edi
.loop:
    add edi, esi
    dec esi
    jnz .loop               ; back edge
    mov [var], edi
    cmp edi, 100
    jb .done
    mov dword [var], 0
.done:
    ret
