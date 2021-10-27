#include "assembly_utils.h"

PPEB GetPEB(void) {
  PPEB ptr;
  asm("movl %%fs:0x30, %0" : "=r"(ptr));
  return ptr;
}

void RaiseInt1(void) {
  asm("int $1");
}

void RaiseInt3(void) {
  asm("int $3");
}