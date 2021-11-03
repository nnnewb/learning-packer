## development requires

**Windows only**.

- MSYS2
- `mingw-w64-clang-i686-toolchain` install by `pacman` package manager in MSYS2 command prompt
- `mingw-w64-i686-toolchain` install by `pacman` package manager in MSYS2 command prompt

Add `/path/to/your/msys64/clang32/bin` and `/path/to/your/msys64/mingw32/bin` to your PATH environment variable.

## version pinning

LLVM/clang version:

```plain
clang version 13.0.0
Target: i686-w64-windows-gnu
Thread model: posix
InstalledDir: C:/Users/weakptr/scoop/apps/msys2/current/clang32/bin
```

## build obfuscator module

```shell
cd obfuscator
mkdir build
cd build
cmake .. -G Ninaj -DCMAKE_C_COMPILER=clang
cmake --build . --config Debug
# if everything is ok, bcf.dll should appear in packer8/obfuscator/build
cp bcf.dll ../../
```

## build packed program

```shell
cd packer8
python build.py
```

## FAQ

Q: build.py shown unknown error 0xC1
A: cause by missing DLL dependencies, please correct your PATH
