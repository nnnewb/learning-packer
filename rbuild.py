import struct
import png

ROW_LEN = 256

with open('example.exe', 'rb') as f:
    arr = []
    content = f.read()
    print('original size', len(content))
    content = struct.pack('<I', len(content))+content

    for i in range(len(content)//ROW_LEN):
        t = content[i*ROW_LEN:i*ROW_LEN+ROW_LEN]
        arr.append(t)

    png.from_array(arr, 'L').save('test.png')

reader = png.Reader(filename='test.png')
width, height, values, info = reader.read_flat()
size, = struct.unpack('<I', bytes(values)[:4])
content = bytes(values)[4:size]
print('original size', size)
print(info)
with open('extract.exe', 'wb+') as f:
    f.write(content)
