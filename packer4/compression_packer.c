#include "zlib.h"

// decompress by zlib
int decompress(void *compressed, size_t length, void *decompressed, size_t decompressed_length) {
  z_stream inflate_stream;
  inflate_stream.zalloc = Z_NULL;
  inflate_stream.zfree = Z_NULL;
  inflate_stream.opaque = Z_NULL;
  inflate_stream.avail_in = (uInt)length;
  inflate_stream.next_in = (Bytef *)compressed;
  inflate_stream.avail_out = (uInt)decompressed_length;
  inflate_stream.next_out = (Bytef *)decompressed;
  inflateInit(&inflate_stream);

  int err = inflate(&inflate_stream, Z_NO_FLUSH);
  if (err != Z_STREAM_END) {
    inflateEnd(&inflate_stream);
    return err;
  }

  inflateEnd(&inflate_stream);
  return 0;
}