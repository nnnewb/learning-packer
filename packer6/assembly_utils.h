#ifndef ASSEMBLY_UTILS_H_
#define ASSEMBLY_UTILS_H_
#include <winternl.h>


#ifdef __cplusplus
extern "C" {
#endif

extern PPEB GetPEB(void);
extern void RaiseInt1(void);
extern void RaiseInt3(void);

#ifdef __cplusplus
}
#endif

#endif