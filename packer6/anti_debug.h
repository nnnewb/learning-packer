#ifndef ANTI_DEBUG_H_
#define ANTI_DEBUG_H_

#include <windows.h>

void anti_debug_by_isDebuggerPresent(void);
void anti_debug_by_PEB_BeingDebugged(void);
void anti_debug_by_RtlGetNtGlobalFlags(void);
void anti_debug_by_PEB_HeapFlags(void);
void anti_debug_by_CheckRemoteDebuggerPresent(void);
void anti_debug_by_NtQueryInformationProcess(void);
void anti_debug_by_NtQueryInformationProcess_BasicInformation(void);
void anti_debug_by_DebugRegister(void);
void anti_debug_by_HideFromDebugger(void);
void anti_debug_by_VEH_INT1(void);
void anti_debug_by_VEH_INT3(void);
void anti_debug_by_VEH_INVALID_HANDLE(void);
// TODO: somehow not work on x32dbg
void anti_debug_by_VEH_OutputDebugException(void);
// TODO: somehow not work on windows 10/MinGW, need more test.
void anti_debug_by_SetLastError(void);
void anti_debug_by_SoftwareBreakPoint(PBYTE addr);

#endif