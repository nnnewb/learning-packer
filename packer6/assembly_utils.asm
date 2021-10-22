; nasm <filename>.asm -f win32 -o assembly_utils.o

section .text
    global _GetPEB

_GetPEB:
    mov eax,[fs:30h]
    retn

section .data
