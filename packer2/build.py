
# %%
import lief
from subprocess import STDOUT, CalledProcessError, check_output


# %%
# compile origin demo program
try:
    check_output('gcc example.c -m32 -O2 -o example.exe', shell=True, stderr=STDOUT)
except CalledProcessError as e:
    print(f'[!] demo program compilation failed, {e.stdout.decode()}')
    raise

binary = lief.PE.parse('example.exe')
print('[+] compile origin demo program success.')

# %%
# compile loader program
compile_args = [
    'loader.c',
    '-m32',
    '-O2',
    '-Wall',
    '-Wl,--entry=__start',
    '-nodefaultlibs',
    '-nostartfiles',
    '-lkernel32',
    '-o',
    'loader.exe'
]

try:
    check_output(' '.join(['gcc', *compile_args]), shell=True, stderr=STDOUT)
    print('[+] compile loader program success.')
except CalledProcessError as e:
    print(f'[!] loader compilation failed, {e.stdout.decode()}')
    raise

loader = lief.PE.parse('loader.exe')

# %%
# add packed section
with open('example.exe', 'rb') as f:
    packed_section = lief.PE.Section('.packed')
    packed_section.content = list(f.read())
    packed_section.characteristics = (lief.PE.SECTION_CHARACTERISTICS.MEM_READ |
                                      lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA)
    loader.add_section(packed_section)

# build output binary
builder = lief.PE.Builder(loader)
builder.build()
builder.write('packed.exe')
print('[+] create packed binary success.')
