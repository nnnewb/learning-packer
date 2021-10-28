#ifndef LOAD_PE_H_
#define LOAD_PE_H_
#include <windows.h>
#include <winnt.h>

void *load_PE(char *PE_data);
void fix_iat(char *p_image_base, IMAGE_NT_HEADERS *p_NT_headers);
void fix_base_reloc(char *p_image_base, IMAGE_NT_HEADERS *p_NT_headers);

#endif