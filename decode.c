#include "png.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8, *u8p;
typedef uint32_t u32, *u32p;

// decode PNG in memory
// https://stackoverflow.com/questions/53237065/using-libpng-1-2-to-write-rgb-image-buffer-to-png-buffer-in-memory-causing-segme
u8p read_png(u8p data, size_t length) {
  png_image image;
  memset(&image, 0, sizeof(image));
  image.version = PNG_IMAGE_VERSION;
  if (png_image_begin_read_from_memory(&image, data, length) == 0) {
    return NULL;
  }

  png_bytep buffer;
  image.format = PNG_FORMAT_GRAY;
  size_t input_data_length = PNG_IMAGE_SIZE(image);
  buffer = (png_bytep)malloc(input_data_length);
  memset(buffer, 0, input_data_length);

  if (png_image_finish_read(&image, NULL, buffer, 0, NULL) == 0) {
    return NULL;
  }

  return (u8p)buffer;
}
