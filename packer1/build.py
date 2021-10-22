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

print('[+] compilation success. Now you can run loader program "./loader.exe ./example.exe"')