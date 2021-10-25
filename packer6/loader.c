#include "anti_debug.h"
#include "load_pe.h"
#include <Windows.h>
#include <stdlib.h>
#include <string.h>
#include <winnt.h>

int _start(void) {
  anti_debug_by_isDebuggerPresent();
  anti_debug_by_PEB_BeingDebugged();
  anti_debug_by_PEB_HeapFlags();
  anti_debug_by_TF();
  anti_debug_by_CheckRemoteDebuggerPresent();

  char *unpacker_VA = (char *)GetModuleHandleA(NULL);

  IMAGE_DOS_HEADER *p_DOS_header = (IMAGE_DOS_HEADER *)unpacker_VA;
  IMAGE_NT_HEADERS *p_NT_headers = (IMAGE_NT_HEADERS *)(((char *)unpacker_VA) + p_DOS_header->e_lfanew);
  IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER *)(p_NT_headers + 1);

  char *packed = NULL;
  char packed_section_name[] = ".packed";

  for (int i = 0; i < p_NT_headers->FileHeader.NumberOfSections; i++) {
    if (strcmp((char *)sections[i].Name, packed_section_name) == 0) {
      packed = unpacker_VA + sections[i].VirtualAddress;
      break;
    }
  }

  if (packed != NULL) {
    void (*entrypoint)(void) = (void (*)(void))load_PE(packed);
    entrypoint();
  }

  return 0;
}