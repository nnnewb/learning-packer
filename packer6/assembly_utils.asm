; nasm <filename>.asm -f win32 -o assembly_utils.o

section .text
    global _GetPEB
    global _RaiseInt1
    global _RaiseInt3

_GetPEB:
    mov eax,[fs:30h]
    retn

_RaiseInt1:
    pushfd
    or [esp],dword 0x100
    popfd
    retn

_RaiseInt3:
    int 3
    retn

section .data
