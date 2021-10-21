#ifndef COMPRESSION_PACKER_H_
#define COMPRESSION_PACKER_H_
#include <stddef.h>

#ifdef __cplusplus
external "C" {
#endif

  int decompress(void *compressed, size_t length, void *decompressed, size_t decompressed_length);

#ifdef __cplusplus
}
#endif

#endif