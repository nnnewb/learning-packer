# %%
import logging
import sys
from os import path

from lief import PE

logging.basicConfig(format='[%(asctime)s] %(levelname)1s %(name)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)

sys.path.append(path.abspath(path.join(path.dirname(__file__), '..')))
from builder.cctarget import CCTarget

# %%
# compile origin demo program
demo = CCTarget('example.exe')
demo.add_c_flags('-m32', '-O2')
demo.add_sources('example.c')
demo.build()
print('[+] compile origin demo program success.')


# %%
loader_target = CCTarget('loader.exe')
loader_target.add_sources('loader.c', 'load_pe.c')
loader_target.add_c_flags('-m32', '-O2', '-Wall')
loader_target.add_ld_flags(
    '-Wl,--entry=__start',
    '-nodefaultlibs',
    '-nostartfiles',
    '-lkernel32',
    '-luser32',
    '-lmsvcrt'
)
loader_target.build()
print('[+] compile loader program success.')

# %%
# add packed section
packed_section = PE.Section('.packed')
with open(demo.target_binary_path, 'rb') as f:
    packed_section.content = list(f.read())
    packed_section.characteristics = (PE.SECTION_CHARACTERISTICS.MEM_READ |
                                      PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA)

# build output binary
loader = PE.parse(loader_target.target_binary_path)
loader.add_section(packed_section)
builder = PE.Builder(loader)
builder.build()
builder.write('packed.exe')
print('[+] create packed binary success.')
