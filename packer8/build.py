# %%
import logging
import subprocess
import sys
from os import path

from lief import PE
from subprocess import run

logging.basicConfig(format='[%(asctime)s] %(levelname)1s %(name)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)

sys.path.append(path.abspath(path.join(path.dirname(__file__), '..')))
from builder.cctarget import CCTarget

# %%
# compile origin demo program
demo = CCTarget('example.exe', 'clang', 'clang')
demo.add_c_flags('-m32', '-O2')
demo.add_sources('example.c')
demo.build()
print('[+] compile origin demo program success.')

# %%

if not path.exists('bcf.dll'):
    print(f'[!] you must build obfuscator plugin first')
    print(f'    see {path.abspath(path.dirname(__file__))}/README.md for how to build LLVM obfuscator module.')
    exit(1)

proc = run(
    'clang '
    '-v '
    '-Xclang '
    '-load '
    '-Xclang '
    'bcf.dll '
    # explicitly disable new pass manager
    '-fno-experimental-new-pass-manager '
    '-m32 '
    '-O0 '
    '-Wall '
    'loader.c '
    'load_pe.c '
    '-Wl,--entry=__start '
    '-nodefaultlibs '
    '-nostartfiles '
    '-lkernel32 '
    '-luser32 '
    '-lmsvcrt '
    '-o '
    'build/bin/loader.exe', shell=True)
if proc.returncode != 0:
    raise Exception("compile failed")

print('[+] compile loader program success.')

# %%
# add packed section
packed_section = PE.Section('.packed')
with open(demo.target_binary_path, 'rb') as f:
    packed_section.content = list(f.read())
    packed_section.characteristics = (PE.SECTION_CHARACTERISTICS.MEM_READ |
                                      PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA)

# build output binary
loader = PE.parse('build/bin/loader.exe')
loader.add_section(packed_section)
builder = PE.Builder(loader)
builder.build()
builder.write('packed.exe')
print('[+] create packed binary success.')
