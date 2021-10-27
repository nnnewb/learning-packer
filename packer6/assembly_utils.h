#ifndef ASSEMBLY_UTILS_H_
#define ASSEMBLY_UTILS_H_
#include <winternl.h>

#ifdef __cplusplus
extern "C" {
#endif

PPEB GetPEB(void);
void RaiseInt1(void);
void RaiseInt3(void);

#ifdef __cplusplus
}
#endif

#endif