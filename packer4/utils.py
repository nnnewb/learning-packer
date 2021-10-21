from subprocess import STDOUT, run, PIPE


def align(x, al):
    """ return <x> aligned to <al> """
    return ((x+(al-1))//al)*al


class CompilationError(Exception):
    def __init__(self, code, output) -> None:
        super().__init__(f'compilation failed')
        self.code = code
        self.output = output

    def __str__(self) -> str:
        return f'compilation failed: compiler exit code {self.code}'

    def __repr__(self) -> str:
        return f'<CompilationError code={self.code}>'


def compile(sources, flags):
    args = ''
    compiler = 'gcc'

    args += ''
    if isinstance(sources, (str, bytes)):
        args += sources
    elif isinstance(sources, (list, tuple)):
        args += ' '.join(sources)

    args += ' '
    if isinstance(flags, (str, bytes)):
        args += flags
    elif isinstance(flags, (list, tuple)):
        args += ' '.join(flags)

    cmd = f'{compiler} {args}'
    proc = run(cmd, shell=True, stderr=STDOUT)
    if proc.returncode != 0:
        raise CompilationError(proc.returncode, proc.stdout)


def windres(sources, output):
    executable = 'windres'
    args = ''
    if isinstance(sources, (str, bytes)):
        args += sources
    elif isinstance(sources, (list, tuple)):
        args += ' '.join(sources)

    cmd = f'{executable} {args} -o {output}'
    proc = run(cmd, shell=True, stderr=STDOUT)
    if proc.returncode != 0:
        raise CompilationError(proc.returncode, proc.stdout)
