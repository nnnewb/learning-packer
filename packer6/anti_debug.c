#include "anti_debug.h"
#include <debugapi.h>
#include <processthreadsapi.h>
#include <windows.h>

void anti_debug_by_isDebuggerPresent(void) {
  if (IsDebuggerPresent() == TRUE) {
    MessageBoxA(NULL, "debugger detected", "IsDebuggerPresent", MB_OK);
  }
}

void anti_debug_by_PEB(void) {
  PVOID peb = GetPEB();
}
