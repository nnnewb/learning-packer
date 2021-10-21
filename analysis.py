import lief
from lief import PE

packed = PE.parse('packed.exe')
loader = PE.parse('shifted-loader.exe')

with open('packed-analysis.txt', 'w+', encoding='utf-8') as out:
    print('-----'*20, file=out)
    print('packed.exe', file=out)
    print('-----'*20, file=out)
    print(packed.header, file=out)
    print(packed.optional_header, file=out)

    for entry in packed.data_directories:
        print(entry, file=out)

    for s in packed.sections:
        print(s, file=out)

with open('loader-analysis.txt', 'w+', encoding='utf-8') as out:
    print('-----'*20, file=out)
    print('shifted-loader.exe', file=out)
    print('-----'*20, file=out)
    print(loader.header, file=out)
    print(loader.optional_header, file=out)

    for entry in loader.data_directories:
        print(entry, file=out)

    for s in loader.sections:
        print(s, file=out)
