# %%
import struct
import zlib
from subprocess import STDOUT, CalledProcessError, check_output

import lief

def align(x, al):
    """ return <x> aligned to <al> """
    return ((x+(al-1))//al)*al


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
# calculate shift offset and reserved section size
image_base = binary.optional_header.imagebase
lowest_rva = min([s.virtual_address for s in binary.sections])
highest_rva = max([s.virtual_address + s.size for s in binary.sections])
sect_alignment = binary.optional_header.section_alignment
print('[+] analyze origin demo program binary success.')

# %%
# compile shifted loader program
compile_args = [
    'loader.c',
    'minilzo/minilzo.c',
    '-m32',
    '-O2',
    '-Wall',
    '-I.',
    '-Iminilzo',
    '-Wl,--entry=__start',
    '-nodefaultlibs',
    '-nostartfiles',
    '-lkernel32',
    '-luser32',
    '-lmsvcrt',
    '-lz',
    f'-Wl,--image-base={hex(image_base)}',
    f'-Wl,--section-start=.text={hex(align(image_base+highest_rva,sect_alignment))}',
    '-o',
    'shifted-loader.exe'
]

try:
    check_output(' '.join(['gcc', *compile_args]), shell=True, stderr=STDOUT)
    print('[+] compile shifted loader program success.')
except CalledProcessError as e:
    print(f'[!] loader compilation failed, {e.stdout.decode()}')
    raise

shifted_loader = lief.PE.parse('shifted-loader.exe')
sect_alignment = shifted_loader.optional_header.section_alignment
file_alignment = shifted_loader.optional_header.file_alignment

# %%
# create new binary from scratch
output = lief.PE.Binary('packed', lief.PE.PE_TYPE.PE32)

# copy essential fields from shifted_loader
output.optional_header.imagebase = shifted_loader.optional_header.imagebase
output.optional_header.section_alignment = shifted_loader.optional_header.section_alignment
output.optional_header.file_alignment = shifted_loader.optional_header.file_alignment

# disable ASLR
output.optional_header.dll_characteristics = 0

# add .alloc section
allocate_size = align(highest_rva-lowest_rva, sect_alignment)
allocate_section = lief.PE.Section(".alloc")
allocate_section.virtual_address = lowest_rva
allocate_section.virtual_size = allocate_size
allocate_section.characteristics = (lief.PE.SECTION_CHARACTERISTICS.MEM_READ
                                    | lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE
                                    | lief.PE.SECTION_CHARACTERISTICS.CNT_UNINITIALIZED_DATA)
output.add_section(allocate_section)

# copy sections
for s in shifted_loader.sections:
    # let lief recalculate section offset and sizeof raw data
    s.offset = 0
    s.sizeof_raw_data = 0
    output.add_section(s)

# add packed section
with open('example.exe', 'rb') as f:
    file_content = f.read()
    origin_length = len(file_content)
    compressed = zlib.compress(file_content, 9)  # best compression
    compressed_length = len(compressed)
    section_content = struct.pack('<II', compressed_length, origin_length)
    section_content += compressed

    packed_section = lief.PE.Section('.packed')
    packed_section.content = list(section_content)
    packed_section.characteristics = (lief.PE.SECTION_CHARACTERISTICS.MEM_READ |
                                      lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA)
    output.add_section(packed_section)

# copy data directories
for i in range(0, 15):
    src = shifted_loader.data_directories[i]
    output.data_directories[i].rva = src.rva
    output.data_directories[i].size = src.size

# correct number of data directories
# warning: size of data directories may disagree with IMAGE_NT_HEADERS.DataDirectory in winnt.h
output.optional_header.numberof_rva_and_size = len(output.data_directories)
# copy original address of entrypoint
output.optional_header.addressof_entrypoint = shifted_loader.optional_header.addressof_entrypoint
# let lief recalculate size of image
output.optional_header.sizeof_image = 0

# build output binary
builder = lief.PE.Builder(output)
builder.build()
builder.write('packed.exe')
print('[+] create packed binary success.')
