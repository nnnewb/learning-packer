#include "anti_debug.h"
#include "assembly_utils.h"
#include <debugapi.h>
#include <processthreadsapi.h>
#include <tlhelp32.h>
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

// does program caught single step exception
BOOL SEHCaughtSingleStepException = FALSE;

LONG CALLBACK exceptEx(_In_ EXCEPTION_POINTERS *lpEP) {
  switch (lpEP->ExceptionRecord->ExceptionCode) {
  case EXCEPTION_SINGLE_STEP:
    // handle single step exception if not handled by debugger
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
  // https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter
  SetUnhandledExceptionFilter(exceptEx);
  // https://docs.microsoft.com/zh-cn/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler?redirectedfrom=MSDN
  // https://docs.microsoft.com/en-us/windows/win32/api/winnt/nc-winnt-pvectored_exception_handler
  AddVectoredExceptionHandler(0, my_seh_handler);
  RaiseInt1();
  RemoveVectoredExceptionHandler(my_seh_handler);
  if (SEHCaughtSingleStepException == FALSE) {
    MessageBoxA(NULL, "debugger detected", "SEH", MB_OK);
  }
}

void anti_debug_by_CheckRemoteDebuggerPresent(void) {
  BOOL isRemoteDebuggerPresent = FALSE;
  if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent)) {
    if (isRemoteDebuggerPresent == TRUE) {
      MessageBoxA(NULL, "debugger detected", "CheckRemoteDebuggerPresent", MB_OK);
    }
  }
}

void anti_debug_by_NtQueryInformationProcess(void) {
  HMODULE ntdll = LoadLibrary(TEXT("ntdll.dll"));
  if (ntdll == NULL) {
    abort();
  }

  FARPROC ntQueryInfoProc = GetProcAddress(ntdll, "NtQueryInformationProcess");
  if (ntQueryInfoProc == NULL) {
    abort();
  }

  DWORD isDebuggerPresent = FALSE;
  NTSTATUS status = ntQueryInfoProc(GetCurrentProcess(), ProcessDebugPort, &isDebuggerPresent, sizeof(DWORD), NULL);
  if (status == 0 && isDebuggerPresent) {
    MessageBoxA(NULL, "debugger detected", "NtQueryInformationProcess", MB_OK);
    return;
  }

  // ... ProcessDebugObject
  // ... ProcessDebugFlags
}

void anti_debug_by_NtQueryInformationProcess_BasicInformation(void) {
  HMODULE ntdll = LoadLibrary(TEXT("ntdll.dll"));
  if (ntdll == NULL) {
    abort();
  }

  FARPROC ntQueryInfoProc = GetProcAddress(ntdll, "NtQueryInformationProcess");
  if (ntQueryInfoProc == NULL) {
    abort();
  }

  PROCESS_BASIC_INFORMATION info;
  NTSTATUS status = ntQueryInfoProc(GetCurrentProcess(), ProcessBasicInformation, &info, sizeof(info), NULL);
  if (status == 0) {
    HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcSnap == NULL) {
      abort();
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcSnap, &pe32)) {
      abort();
    }

    do {
      if (pe32.th32ProcessID == info.InheritedFromUniqueProcessId) {
#ifdef UNICODE
        if (wcscmp(L"devenv.exe", pe32.szExeFile) == 0 || wcscmp(L"x32dbg.exe", pe32.szExeFile) == 0 ||
            wcscmp(L"x64dbg.exe", pe32.szExeFile) == 0 || wcscmp(L"ollydbg.exe", pe32.szExeFile) == 0) {
#else
        if (strcmp("devenv.exe", pe32.szExeFile) == 0 || strcmp("x32dbg.exe", pe32.szExeFile) == 0 ||
            strcmp("x64dbg.exe", pe32.szExeFile) == 0 || strcmp("ollydbg.exe", pe32.szExeFile) == 0) {
#endif
          MessageBoxA(NULL, "debugger detected", "BasicInformation", MB_OK);
          CloseHandle(hProcSnap);
          return;
        }
      }
    } while (Process32Next(hProcSnap, &pe32));
  }
}
