#include "anti_debug.h"
#include "load_pe.h"
#include <Windows.h>
#include <stdlib.h>
#include <string.h>
#include <winnt.h>

int _start(void) {
  // too powerful, can't debug
  // anti_debug_by_HideFromDebugger();
  // anti_debug_by_RtlGetNtGlobalFlags();
  // anti_debug_by_isDebuggerPresent();
  // anti_debug_by_PEB_BeingDebugged();
  // anti_debug_by_PEB_HeapFlags();
  // anti_debug_by_CheckRemoteDebuggerPresent();
  // anti_debug_by_NtQueryInformationProcess();
  // anti_debug_by_NtQueryInformationProcess_BasicInformation();
  // anti_debug_by_DebugRegister();
  // anti_debug_by_VEH_INT1();
  // anti_debug_by_VEH_INT3();
  // TODO: somehow not work on x32dbg
  // anti_debug_by_VEH_OutputDebugException();
  anti_debug_by_VEH_INVALID_HANDLE();
  // TODO: somehow not work on windows 10/MinGW, need more test.
  // anti_debug_by_SetLastError();

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