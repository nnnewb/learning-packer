#ifndef JUNK_CODE_H_
#define JUNK_CODE_H_

#define ANTI_LINEAR_DISASSEMBLE_ALGORITHM_1 asm("jmp next\n.byte 0xe8;\nnext:\n")
#define ANTI_CONTROLFLOW_DISASSEMBLE_ALGORITHM_1 asm(".byte 0xeb,0xff,0xc0\ndec %eax\n")

#endif