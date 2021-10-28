from os import lstat, makedirs, path
import pathlib
import re
from subprocess import PIPE, STDOUT, run
from typing import Sequence, Set
import locale

from builder.exceptions import CompilationError, CompilerFeatureProbeFail, NoSuchFileOrDirectoryException
from logging import Logger, debug, getLogger

_CC_LOGGER: Logger = getLogger('CC')


class _CCSource:
    def __init__(self, path, compiler, flags, output) -> None:
        self._src_path = path
        self._compiler = compiler
        self._flags = flags
        self._obj_path = output

    @staticmethod
    def is_cpp(filename: str):
        return re.match(r'.*?\.(cc|cpp|cxx)', filename) is not None

    @property
    def obj_st_mtime_ns(self):
        return lstat(self._obj_path).st_mtime_ns

    @property
    def src_st_mtime_ns(self):
        return lstat(self._src_path).st_mtime_ns

    @property
    def src_path(self):
        return self._src_path

    @property
    def obj_path(self):
        return self._obj_path

    @property
    def need_recompile(self):
        # TODO: 要跟踪所有头文件来确定是否需要重新编译
        if not path.exists(self._obj_path):
            return True

        return lstat(self._src_path).st_mtime_ns >= lstat(self._obj_path).st_mtime_ns

    def compile(self):
        # TODO: -o 并不通用
        cmd = [self._compiler, self._src_path, *self._flags, '-c', '-o', self._obj_path]
        _CC_LOGGER.debug('Run: ' + ' '.join(cmd))
        proc = run(cmd, stdout=PIPE, stderr=STDOUT)
        if proc.returncode != 0:
            raise CompilationError(
                f'{self._src_path}: compile fail\n{proc.stdout.decode(locale.getpreferredencoding())}\n')




class _CCBuilder:
    def __init__(self, sources: Sequence[_CCSource], compiler: str, linker: str, c_flags: Sequence[str], cxx_flags: Sequence[str], ld_flags: Sequence[str], output: str):
        self._compiler = compiler
        self._linker = linker
        self._c_flags = c_flags
        self._cxx_flags = cxx_flags
        self._ld_flags = ld_flags
        self._sources: Sequence[_CCSource] = sources
        self._output = output

    @property
    def need_rebuild(self):
        if not path.exists(self._output):
            return True
        mtime = lstat(self._output).st_mtime_ns
        return any(map(lambda src: src.src_st_mtime_ns >= mtime, self._sources))

    def _compile(self):
        for src in self._sources:
            # if not src.need_recompile:
            #     _CC_LOGGER.debug(f'Skip: {src._src_path}')
            #     continue
            _CC_LOGGER.info(f'Compiling: {src._src_path}')
            src.compile()

    def _link(self):
        _CC_LOGGER.info(f'Linking: {self._output}')
        obj_files = [src.obj_path for src in self._sources]
        # TODO: -o 并不通用
        cmd = [self._linker, *obj_files, *self._ld_flags, '-o', self._output]
        _CC_LOGGER.debug(' '.join(cmd))
        proc = run(cmd, stdout=PIPE, stderr=STDOUT)
        if proc.returncode != 0:
            raise CompilationError(f'{self._output}: link fail\n{proc.stdout.decode(locale.getpreferredencoding())}\n')

    def build(self):
        _CC_LOGGER.info(f'Building: {self._output}')
        self._compile()
        self._link()
        # if self.need_rebuild:
        #     self._compile()
        #     self._link()


class CCTarget:
    def __init__(self, name, compiler='gcc', linker='gcc', binary_dir='build/bin', obj_dir='build/obj') -> None:
        self.name = name
        self._compiler: str = compiler
        self._linker: str = linker
        self._binary_dir: str = binary_dir
        self._obj_dir: str = obj_dir

        self._sources: Set[str] = set()
        self._LD_FLAGS: Set[str] = set()
        self._C_FLAGS: Set[str] = set()
        self._CXX_FLAGS: Set[str] = set()

    @property
    def compiler(self):
        return self._compiler

    @compiler.setter
    def compiler(self, compiler):
        self._compiler = compiler

    @property
    def linker(self):
        return self._linker

    @linker.setter
    def linker(self, linker):
        self._linker = linker

    @property
    def binary_dir(self):
        return self._binary_dir

    @binary_dir.setter
    def binary_dir(self, binary_dir):
        self._binary_dir = binary_dir

    @property
    def obj_dir(self):
        return self._obj_dir

    @property
    def c_flags(self):
        return self._C_FLAGS

    @property
    def cxx_flags(self):
        return self._CXX_FLAGS

    @property
    def ld_flags(self):
        return self._LD_FLAGS

    @property
    def target_binary_path(self):
        return path.join(self.binary_dir, self.name)

    def add_include_dir(self, *includes):
        for inc in includes:
            if path.exists(inc):
                self._C_FLAGS.add(f'-I{inc}')
                self._CXX_FLAGS.add(f'-I{inc}')
            else:
                raise NoSuchFileOrDirectoryException(f'{inc}: include dir not exists')

    def add_link_libraries(self, *libraries):
        for lib in libraries:
            self._LD_FLAGS.add(f'-l{lib}')

    def add_c_flags(self, *flags):
        for flag in flags:
            self._C_FLAGS.add(flag)

    def add_cxx_flags(self, *flags):
        for flag in flags:
            self._CXX_FLAGS.add(flag)

    def add_c_cxx_flags(self, *flags):
        for flag in flags:
            self._C_FLAGS.add(flag)
            self._CXX_FLAGS.add(flag)

    def add_ld_flags(self, *ld_flags):
        for flag in ld_flags:
            self._LD_FLAGS.add(flag)

    def add_sources(self, *sources):
        for src in sources:
            if not path.exists(src):
                raise NoSuchFileOrDirectoryException(f'{src}: source file not exists')
            self._sources.add(path.abspath(src))

    def build(self):
        makedirs(self.binary_dir, exist_ok=True)
        makedirs(self.obj_dir, exist_ok=True)
        sources = [
            _CCSource(
                path.abspath(src),
                self.compiler,
                self.c_flags if not _CCSource.is_cpp(src) else self.cxx_flags,
                path.abspath(path.join(self.obj_dir, pathlib.Path(src).with_suffix('.obj').name))
            )
            for src in self._sources
        ]
        bin = path.abspath(path.join(self.binary_dir, self.name))
        builder = _CCBuilder(sources, self.compiler, self.linker, self.c_flags, self.cxx_flags, self.ld_flags, bin)
        builder.build()

        _CC_LOGGER.info(f'Target build: {bin}')
