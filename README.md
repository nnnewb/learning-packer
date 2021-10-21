# learning-packer

## 开发环境

开发工具：

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

注意需要把 `[/path/to/your/msys64]/mingw32/bin` 加入 `PATH` 环境变量。

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
