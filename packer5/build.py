# %%
from os import path
import struct
import png

from lief import PE

from utils import align, compile, windres

src_dir = path.dirname(__file__)

# %%
# compile origin demo program
compile(path.join(src_dir, 'example.c'), '-m32 -O2 -o example.exe')
binary = PE.parse('example.exe')
print('[+] compile origin demo program success.')

# %%
IMG_PATH = 'packer5-packed.png'
ROW_LEN = 256
with open('example.exe', 'rb') as f:
    arr = []
    content = f.read()
    content = struct.pack('<I', len(content))+content

    for i in range(len(content)//ROW_LEN):
        t = content[i*ROW_LEN:i*ROW_LEN+ROW_LEN]
        arr.append(t)

    img = png.from_array(arr, 'L').save(IMG_PATH)

# %%
windres(path.join(src_dir, 'rsrc.rc'), path.join(src_dir, 'rsrc.o'))
print('[+] compile resource success.')

# %%
# compile shifted loader program
cflags = [
    '-m32',
    '-O2',
    '-Wall',
    '-I.',
    '-Wl,--entry=__start',
    '-nodefaultlibs',
    '-nostartfiles',
    '-lkernel32',
    '-luser32',
    '-lmsvcrt',
    '-lpng',
    '-o',
    'packed.exe'
]
compile([path.join(src_dir, src) for src in ['loader.c', 'png_decode.c', 'rsrc.o']], cflags)
print('[+] compile loader with resource success.')
