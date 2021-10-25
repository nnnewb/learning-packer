#include "anti_debug.h"
#include "assembly_utils.h"
#include <debugapi.h>
#include <processthreadsapi.h>
#include <windows.h>

void anti_debug_by_isDebuggerPresent(void) {
  if (IsDebuggerPresent() == TRUE) {
    MessageBoxA(NULL, "debugger detected", "IsDebuggerPresent", MB_OK);
  }
}

void anti_debug_by_PEB_BeingDebugged(void) {
  PPEB peb = GetPEB();
  if (peb->BeingDebugged != 0) {
    MessageBoxA(NULL, "debugger detected", "PEB->BeingDebugged", MB_OK);
  }
}

// detect debugger by _HEAP->Flags and _HEAP->ForceFlags
//
// <== windbg display type ==>
//
// 0:000> dt _peb processheap
// ntdll!_PEB
//    +0x018 ProcessHeap : Ptr32 Void
// 0:000> dt _heap flags
// ntdll!_HEAP
//    +0x040 Flags : Uint4B
// 0:000> dt _heap forceflags
// ntdll!_HEAP
//    +0x044 ForceFlags : Uint4B
void anti_debug_by_PEB_HeapFlags(void) {
  PPEB peb = GetPEB();
  PVOID heap = *(PDWORD)((PBYTE)peb + 0x18);
  PDWORD heapFlags = (PDWORD)((PBYTE)heap + 0x40);
  PDWORD forceFlags = (PDWORD)((PBYTE)heap + 0x44);

  if (*heapFlags & ~HEAP_GROWABLE || *forceFlags != 0) {
    MessageBoxA(NULL, "debugger detected", "PEB->_HEAP->HeapFlags,ForceFlags", MB_OK);
  }
}

BOOL SEHCaughtSingleStepException = FALSE;

LONG CALLBACK exceptEx(_In_ EXCEPTION_POINTERS *lpEP) {
  switch (lpEP->ExceptionRecord->ExceptionCode) {
  case EXCEPTION_SINGLE_STEP:
    return EXCEPTION_EXECUTE_HANDLER;
  default:
    return EXCEPTION_CONTINUE_SEARCH;
  }
}

LONG NTAPI my_seh_handler(PEXCEPTION_POINTERS exceptionInfo) {
  SEHCaughtSingleStepException = TRUE;
  return EXCEPTION_CONTINUE_EXECUTION;
}

void anti_debug_by_TF(void) {
  SEHCaughtSingleStepException = FALSE;
  SetUnhandledExceptionFilter(exceptEx);
  AddVectoredExceptionHandler(0, my_seh_handler);
  RaiseInt1();
  RemoveVectoredExceptionHandler(my_seh_handler);
  if (SEHCaughtSingleStepException == FALSE) {
    MessageBoxA(NULL, "debugger detected", "SEH", MB_OK);
  }
}
