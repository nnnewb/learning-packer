.section .data

.section .text
    .global _GetPEB
    .global _RaiseInt1
    .global _RaiseInt3

_GetPEB:
    movl %fs:0x30, %eax
    retl

_RaiseInt1:
    pushfl
    orl $100, %esp
    popfl
    ret

_RaiseInt3:
    int $3
    ret
