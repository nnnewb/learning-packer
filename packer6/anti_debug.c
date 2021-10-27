#include "anti_debug.h"
#include "assembly_utils.h"
#include <debugapi.h>
#include <processthreadsapi.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <windows.h>
#include <winternl.h>

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

void anti_debug_by_RtlGetNtGlobalFlags(void) {
  // 两种方式，直接读内存或者用undocumented接口
  PPEB peb = GetPEB();
  if (*(PULONG)((PBYTE)peb + 0x68) & (0x20 | 0x40)) {
    MessageBoxA(NULL, "debugger detected", "PEB->NtGlobalFlag", MB_OK);
  }
  // 或者...
  HMODULE ntdll = LoadLibraryA("ntdll.dll");
  FARPROC proc = GetProcAddress(ntdll, "RtlGetNtGlobalFlags");
  typedef ULONG (*RtlGetNtGlobalFlags_t)(void);
  if (((RtlGetNtGlobalFlags_t)proc)() & (0x20 | 0x40)) {
    MessageBoxA(NULL, "debugger detected", "RtlGetNtGlobalFlags", MB_OK);
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

BOOL volatile VEH_INT1_isDebuggerPresent = FALSE;

LONG CALLBACK VEH_INT1_UnhandledExceptionFilter(_In_ EXCEPTION_POINTERS *lpEP) {
  switch (lpEP->ExceptionRecord->ExceptionCode) {
  case EXCEPTION_SINGLE_STEP:
    // handle single step exception if not handled by debugger
    VEH_INT1_isDebuggerPresent = FALSE;
    return EXCEPTION_CONTINUE_EXECUTION;
  default:
    return EXCEPTION_CONTINUE_SEARCH;
  }
}

void anti_debug_by_VEH_INT1(void) {
  VEH_INT1_isDebuggerPresent = TRUE;
  // https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter
  SetUnhandledExceptionFilter(VEH_INT1_UnhandledExceptionFilter);
  // https://docs.microsoft.com/zh-cn/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler?redirectedfrom=MSDN
  // https://docs.microsoft.com/en-us/windows/win32/api/winnt/nc-winnt-pvectored_exception_handler
  RaiseInt1();
  if (VEH_INT1_isDebuggerPresent == TRUE) {
    MessageBoxA(NULL, "debugger detected", "VEH INT1", MB_OK);
  }
}

BOOL volatile VEH_INT3_isDebuggerPresent = FALSE;

LONG CALLBACK VEH_INT3_UnhandledExceptionFilter(_In_ EXCEPTION_POINTERS *lpEP) {
  switch (lpEP->ExceptionRecord->ExceptionCode) {
  case EXCEPTION_BREAKPOINT:
    // handle single step exception if not handled by debugger
    VEH_INT3_isDebuggerPresent = FALSE;
    lpEP->ContextRecord->Eip += 1;
    return EXCEPTION_CONTINUE_EXECUTION;
  default:
    return EXCEPTION_CONTINUE_SEARCH;
  }
}

void anti_debug_by_VEH_INT3(void) {
  VEH_INT3_isDebuggerPresent = TRUE;
  SetUnhandledExceptionFilter(VEH_INT3_UnhandledExceptionFilter);
  RaiseInt3();
  if (VEH_INT3_isDebuggerPresent == TRUE) {
    MessageBoxA(NULL, "debugger detected", "VEH INT3", MB_OK);
  }
}

// TODO: somehow not work on x32dbg
BOOL VEH_OutputDebugStringException_isDebuggerPresent = FALSE;

LONG CALLBACK VEH_OutputDebugStringException_UnhandledExceptionFilter(_In_ EXCEPTION_POINTERS *lpEP) {
  switch (lpEP->ExceptionRecord->ExceptionCode) {
  case DBG_PRINTEXCEPTION_WIDE_C:
    // handle exception if not handled by debugger
    VEH_OutputDebugStringException_isDebuggerPresent = FALSE;
    return EXCEPTION_CONTINUE_EXECUTION;
  default:
    return EXCEPTION_CONTINUE_SEARCH;
  }
}

void anti_debug_by_VEH_OutputDebugException(void) {
  ULONG_PTR args[4] = {0, 0, 0, 0};
  args[0] = (ULONG_PTR)wcslen(L"debug") + 1;
  args[1] = (ULONG_PTR)L"debug";
  AddVectoredExceptionHandler(0, VEH_OutputDebugStringException_UnhandledExceptionFilter);
  VEH_OutputDebugStringException_isDebuggerPresent = TRUE;
  RaiseException(DBG_PRINTEXCEPTION_WIDE_C, 0, 4, args);
  RemoveVectoredExceptionHandler(VEH_OutputDebugStringException_UnhandledExceptionFilter);
  if (VEH_OutputDebugStringException_isDebuggerPresent == TRUE) {
    MessageBoxA(NULL, "debugger detected", "OutputDebugString", MB_OK);
  }
}

// TODO: somehow not work on x32dbg
LONG CALLBACK VEH_INVALID_HANDLE_UnhandledExceptionFilter(_In_ EXCEPTION_POINTERS *lpEP) {
  switch (lpEP->ExceptionRecord->ExceptionCode) {
  case EXCEPTION_INVALID_HANDLE:
    // if debug present
    MessageBoxA(NULL, "debugger detected", "INVALID HANDLE", MB_OK);
    return EXCEPTION_CONTINUE_EXECUTION;
  default:
    return EXCEPTION_CONTINUE_SEARCH;
  }
}

void anti_debug_by_VEH_INVALID_HANDLE(void) {
  AddVectoredExceptionHandler(0, VEH_INVALID_HANDLE_UnhandledExceptionFilter);
  CloseHandle((HANDLE)0xBAAD);
  RemoveVectoredExceptionHandler(VEH_INVALID_HANDLE_UnhandledExceptionFilter);
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

#ifdef UNICODE
#  define MY_STRCMP wcscmp
#else
#  define MY_STRCMP strcmp
#endif

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
        if (MY_STRCMP(TEXT("devenv.exe"), pe32.szExeFile) == 0 || MY_STRCMP(TEXT("x32dbg.exe"), pe32.szExeFile) == 0 ||
            MY_STRCMP(TEXT("x64dbg.exe"), pe32.szExeFile) == 0 || MY_STRCMP(TEXT("ollydbg.exe"), pe32.szExeFile) == 0) {
          MessageBoxA(NULL, "debugger detected", "BasicInformation", MB_OK);
          CloseHandle(hProcSnap);
          return;
        }
      }
    } while (Process32Next(hProcSnap, &pe32));
  }
}

// detect hardware breakpoint
void anti_debug_by_debug_registers(void) {
  CONTEXT ctx;
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
  if (GetThreadContext(GetCurrentThread(), &ctx)) {
    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
      MessageBoxA(NULL, "debugger detected", "Dr0-Dr3", MB_OK);
    }
  }
}

typedef NTSTATUS(NTAPI *pfnNtSetInformationThread)(_In_ HANDLE ThreadHandle, _In_ ULONG ThreadInformationClass,
                                                   _In_ PVOID ThreadInformation, _In_ ULONG ThreadInformationLength);
void anti_debug_by_HideFromDebugger(void) {
  HMODULE ntdll = LoadLibrary(TEXT("ntdll.dll"));
  if (ntdll == NULL) {
    abort();
  }

  pfnNtSetInformationThread ntSetInfoThread =
      (pfnNtSetInformationThread)GetProcAddress(ntdll, "NtSetInformationThread");
  if (ntSetInfoThread == NULL) {
    abort();
  }

  ntSetInfoThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
  // ... NtCreateThreadEx THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
}

// TODO: somehow not work on windows 10, need more test.
void anti_debug_by_SetLastError(void) {
  SetLastError(0x1234);
  OutputDebugString(TEXT("Hello Debugger!"));
  if (GetLastError() == 0x1234) {
    MessageBoxA(NULL, "debugger detected", "Set/Get LastError", MB_OK);
  }
}
