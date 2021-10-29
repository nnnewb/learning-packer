from os import lstat, makedirs, path
import pathlib
import re
from subprocess import PIPE, STDOUT, run
from typing import Sequence, Set
import locale

from builder.exceptions import CompilationError, CompilerFeatureProbeFail, NoSuchFileOrDirectoryException
from logging import Logger, debug, getLogger

_CC_LOGGER: Logger = getLogger('CC')


class _GccSrcDepProb:
    def __init__(self, src_path: str, dep_path: str) -> None:
        self.src_path = src_path
        self.dep_path = dep_path

    @property
    def need_reprobe(self):
        if not path.exists(self.dep_path):
            return True

        return lstat(self.src_path).st_mtime_ns >= lstat(self.dep_path).st_mtime_ns

    def probe(self):
        if self.need_reprobe:
            cmd = ' '.join(['gcc', self.src_path, '-c', '-MMD', '-MF', self.dep_path])
            proc = run(cmd, shell=True, stdout=PIPE, stderr=STDOUT)
            if proc.returncode != 0:
                output = proc.stdout.decode(locale.getpreferredencoding())
                raise CompilerFeatureProbeFail(f'source dependencies probe fail: {output}')

        dependencies = []
        with open(self.dep_path, 'r', encoding=locale.getpreferredencoding()) as f:
            first = True
            for line in f:
                if first is True:
                    _, paths = line.split(':', 1)
                else:
                    paths = line

                valid_dependencies = filter(lambda s: bool(s), map(lambda s: s.strip(), paths.strip().split(' ')))
                for src_dep_path in valid_dependencies:
                    if src_dep_path[-1] == '\\':
                        src_dep_path = src_dep_path[:-1].strip()

                    if src_dep_path:
                        dependencies.append(src_dep_path)

                if line.endswith('\\'):
                    continue

        return dependencies


class _CCSource:
    def __init__(self, src_path, compiler, compile_flags, obj_path, dep_path):
        """C/C++ source file abstraction

        Args:
            src_path (str): source file absolute path
            compiler (str): compiler absolute path
            compile_flags (List[str]): compiler flags
            obj_path (str): object file absolute path
            dep_path (str): depend definition absolute path
        """
        self._compiler = compiler
        self._src_path = src_path
        self._compile_flags = compile_flags
        self._obj_path = obj_path
        self._dep_path = dep_path
        # TODO: 应该根据compiler选择
        self._is_cpp = re.match(r'.*?\.(cc|cpp|cxx)', self._src_path) is not None
        self._dependencies_probe = _GccSrcDepProb(src_path, self._dep_path)

    @property
    def _obj_modified_at(self):
        return lstat(self._obj_path).st_mtime_ns

    @property
    def _src_modified_at(self):
        return lstat(self._src_path).st_mtime_ns

    @property
    def src_path(self):
        return self._src_path

    @property
    def obj_path(self):
        return self._obj_path

    @property
    def need_recompile(self):
        if not path.exists(self._obj_path):
            return True

        for depend in self._dependencies_probe.probe():
            if lstat(depend).st_mtime_ns >= self._obj_modified_at:
                return True

        return False

    def compile(self):
        # TODO: -o 并不通用
        cmd = [self._compiler, self._src_path, *self._compile_flags, '-c', '-o', self._obj_path]
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

        return any(map(lambda src: src.need_recompile, self._sources))

    def _compile(self):
        for src in self._sources:
            if not src.need_recompile:
                _CC_LOGGER.debug(f'Skip: {src._src_path}')
                continue
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
        if self.need_rebuild:
            self._compile()
            self._link()


class CCTarget:
    def __init__(self, name, compiler='gcc', linker='gcc', bin_dir='build/bin', obj_dir='build/obj', dep_dir='build/dep') -> None:
        self.name = name
        self._compiler: str = compiler
        self._linker: str = linker
        self._bin_dir: str = bin_dir
        self._obj_dir: str = obj_dir
        self._dep_dir: str = dep_dir

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
    def bin_dir(self):
        return self._bin_dir

    @bin_dir.setter
    def bin_dir(self, binary_dir):
        self._bin_dir = binary_dir

    @property
    def obj_dir(self):
        return self._obj_dir

    @property
    def dep_dir(self):
        return self._dep_dir

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
        return path.join(self.bin_dir, self.name)

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
        makedirs(self.bin_dir, exist_ok=True)
        makedirs(self.obj_dir, exist_ok=True)
        makedirs(self.dep_dir, exist_ok=True)
        sources = [
            _CCSource(
                path.abspath(src),
                self.compiler,
                self.c_flags if src.endswith('.c') else self.cxx_flags,
                path.abspath(path.join(self.obj_dir, pathlib.Path(src).with_suffix('.obj').name)),
                path.abspath(path.join(self.dep_dir, pathlib.Path(src).with_suffix('.dep').name))
            )
            for src in self._sources
        ]
        bin = path.abspath(path.join(self.bin_dir, self.name))
        builder = _CCBuilder(sources, self.compiler, self.linker, self.c_flags, self.cxx_flags, self.ld_flags, bin)
        builder.build()

        _CC_LOGGER.info(f'Artifact built: {bin}')
