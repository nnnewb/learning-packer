#ifndef PNG_DECODE_H_
#define PNG_DECODE_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t u8, *u8p;
typedef uint32_t u32, *u32p;

u8p read_program_from_png(u8p data, size_t length);

#ifdef __cplusplus
}
#endif

#endif