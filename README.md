# learning-packer

## 介绍

各案例的主题：

1. 基本的 PE32 程序加载。
2. 从内存加载 PE32 程序。
3. 从内存加载不支持 ASLR 的 PE32 程序。
4. 从内存加载 zlib 压缩过的 PE32 程序。
5. 从资源加载编码为 PNG 灰度图的 PE32 程序。
6. 几种反调试技术。
7. 关于反反汇编(花指令)技术。
8. 基于LLVM Pass 的简单代码混淆技术。

构造输出结果的 python 脚本也可以用 c++ 代码结合 LIEF 库，接口和逻辑都一样。

出于保持简单的考虑，另外 LIEF 也没提供 MinGW 版本的库，所以统一为使用 Python 版本的 LIEF。

*2021年10月22日* 为止，lief 没有提供类型存根，造成 VSCode 对 lief 库的函数和模块无法提供补全提示和即时的代码检查。 为了 VSCode 正确提供 LIEF 库的智能提示，可以使用 mypy 提供的 `stubgen` 脚本生成 `pyi` 存根。

这是可选的，提供存根可以有效提高在 VSCode 里编写代码的体验。

```shell
./venv/Scripts/Activate.ps1
pip install mypy
stubgen -p lief -o typings
```

## 开发环境

开发工具：

- nasm
- Python 3.8
- MSYS2/mingw-w64-i686

Python 第三方包：

- lief
- pypng

```shell
pip install lief pypng
```

C 第三方库：

- zlib
- libpng

```shell
# 在 MSYS2 命令行环境里执行
pacman -Sy mingw-w64-i686-zlib mingw-w64-i686-libpng
```

注意需要把 `nasm` 和 `[/path/to/your/msys64]/mingw32/bin` 加入 `PATH` 环境变量。

## 实验方式

准备好环境之后执行案例目录里的 build.py 脚本即可。

```shell
# pacman -Sy mingw-w64-i686-zlib mingw-w64-i686-libpng
# python38 -m venv venv
# ./venv/Scripts/Activate.ps1
# pip install lief pypng
cd packer4
python build.py
./packed.exe
```

## LICENSE

MIT License

Copyright (c) 2021 weak_ptr [<weak_ptr@outlook.com>](mailto:weak_ptr@outlook.com)
