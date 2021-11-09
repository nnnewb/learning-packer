import locale
import struct
import zlib
from binascii import hexlify
from copy import copy
from subprocess import STDOUT, CalledProcessError, check_output
from PIL import Image
from hashlib import sha256

import png
from pyDes import CBC, PAD_PKCS5, des

width, height, pixels, info = png.Reader(filename='hide.png').read_flat()
hidden = pixels[width*height*4:]
length, = struct.unpack('<I', hidden[:4])
content = hidden[4:length+4]

print('hidden content sha256:', sha256(content).hexdigest())
