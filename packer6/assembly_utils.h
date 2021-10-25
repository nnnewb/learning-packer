#ifndef ASSEMBLY_UTILS_H_
#define ASSEMBLY_UTILS_H_
#include <winternl.h>


#ifdef __cplusplus
extern "C" {
#endif

extern PPEB GetPEB();
extern void RaiseInt1();

#ifdef __cplusplus
}
#endif

#endif