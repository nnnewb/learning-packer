import struct
from subprocess import STDOUT, CalledProcessError, check_call, check_output
from typing import List
import zlib
from copy import copy
from hashlib import sha256
from io import BytesIO

import png
from pyDes import CBC, PAD_PKCS5, des


def compress(filename: str) -> bytes:
    """compress file and return compressed data with original size (4byte) in front
    """
    with open(filename, 'rb') as f:
        content = f.read()
        return struct.pack('<I', len(content)) + zlib.compress(content, level=9)


def encrypt(data: bytes) -> bytes:
    """encrypt data with des algorithm, return encrypted data
    """
    cypher = des('ilF9eKRC', CBC, IV=b'zgOr6NtQ', padmode=PAD_PKCS5)
    return cypher.encrypt(data)


def align(x, al):
    """ return <x> aligned to <al> """
    return ((x+(al-1))//al)*al


def padding(x, al):
    """ return <x> padded to <al> """
    x += b'\0'*(align(len(x), al)-len(x))
    return x


def encode(data: bytes, width_in_pixels: int, depth: int) -> List[bytes]:
    width_in_byte = width_in_pixels*depth
    padded = padding(data, width_in_byte)
    rows: List[bytes] = []

    for r in range(len(padded)//width_in_byte):
        row = bytearray()
        row_begin = r*width_in_byte
        row_end = row_begin+width_in_byte
        for c in range(len(padded[row_begin:row_end])//depth):
            pixel_begin = row_begin+c*depth
            pixel_end = pixel_begin+depth
            pixel: bytes = padded[pixel_begin:pixel_end]
            row.extend(copy(pixel))

        rows.append(copy(bytes(row)))
        row.clear()

    return rows


def hide_in_png_1(original_filename: str, output_filename: str, data: bytes):
    """hide data in png file method 1
    """
    with open(output_filename, 'wb+') as f:
        with open(original_filename, 'rb') as src:
            f.write(src.read())
            f.write(b'----HIDDEN----')
            f.write(data)


def hide_in_png_2(original_filename: str, output_filename: str, data: bytes):
    """hide data in png file method 2
    """
    width, height, rows, info = png.Reader(filename=original_filename).read()
    rows = [row for row in rows]

    # original size before padding so we can restore data from pixels
    hidden = struct.pack('<I', len(data)) + data

    # encode bytes into array of pixels
    encoded = encode(hidden, width, info['planes']*info['bitdepth']//8)
    rows.extend(encoded)

    # write png file into memory
    fakeFile = BytesIO()
    img = png.from_array(rows, 'RGBA')
    img.write(fakeFile)
    img_content = bytearray(fakeFile.getvalue())

    # find IHDR chunk
    IHDR_offset = img_content.find(b'IHDR')
    if IHDR_offset == -1:
        raise Exception('IHDR header not found')

    # modify IHDR chunk data (image height)
    chunk_size, = struct.unpack('>I', img_content[IHDR_offset-4:IHDR_offset])
    img_content[IHDR_offset+8:IHDR_offset+12] = struct.pack('>I', height)

    # recalculating CRC32
    chunk = img_content[IHDR_offset:IHDR_offset+4+chunk_size]
    checksum = zlib.crc32(chunk)
    img_content[IHDR_offset+4+chunk_size:IHDR_offset+4+chunk_size+4] = struct.pack('>I', checksum)

    # write final image
    with open(output_filename, 'wb+') as o:
        o.write(img_content)


if __name__ == '__main__':
    try:
        check_call(['gcc', 'sample.c', '-Wall', '-O3', '-o', 'sample.exe'], stderr=STDOUT)
    except CalledProcessError as err:
        print('compilation fail,', err.output)
        exit(1)

    compressed = compress('sample.exe')
    encrypted = encrypt(compressed)
    hide_in_png_2('anime-girl.png', 'hide.png', encrypted)

    try:
        check_call(['windres', 'rsrc.rc', '-o', 'rsrc.o'], stderr=STDOUT)
    except CalledProcessError as err:
        print('compilation fail,', err.output)
        exit(1)
