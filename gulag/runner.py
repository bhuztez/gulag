__all__ = (
    "Runner", "BinaryMixin", "BytecodeMixin", "ScriptMixin")

from contextlib import nested
import os
from os import EX_OK
from os.path import basename, join, splitext
from shutil import copy, rmtree
from subprocess import Popen, STDOUT, PIPE
from tempfile import mkdtemp

from selinux import (
    getcon, is_selinux_enabled, setexeccon,
    setfilecon, setfscreatecon, fgetfilecon, fsetfilecon)

from .ptrace import PTracedProcess
from .utils import which

assert is_selinux_enabled(), "SELinux is currently disabled"


def parse_category(s):
    l = s.split(":")[5:]
    if not l:
        return set()

    result = set()

    for c in l[0].split(','):
        r = c.split('.', 1)
        if len(r) == 1:
            result.add(int(r[0][1:]))
        else:
            for i in range(int(r[0][1:]), int(r[1][1:])):
                result.add(i)

    return result


def check_category(have, need):
    return bool(parse_category(need) - parse_category(have))


class Runner(object):
    SETYPE = 'sandbox_t'
    FILE_SETYPE = 'sandbox_file_t'
    TEMPDIR_PREFIX = "." + __package__

    def adapt_limit(self, time_limit, rss_limit, vm_limit):
        return time_limit, rss_limit, vm_limit

    def normalize_usage(self, cputime, maxrss, maxvm):
        return cputime, maxrss, maxvm

    def __init__(self, src_path, filename=None):
        self._src_path = src_path
        self._filename = filename or basename(src_path)
        self._con = getcon()[1].split(":")

        setfscreatecon(self.filecon(self.COMPILE_LEVEL))
        self._tempdir = mkdtemp(prefix=self.TEMPDIR_PREFIX)
        setfscreatecon(None)

    def execcon(self, level):
        return "%s:%s:%s:%s" % (
            self._con[0], self._con[1], self.SETYPE, level)

    def filecon(self, level):
        return "%s:%s:%s:%s" % (
            self._con[0], "object_r", self.FILE_SETYPE, level)

    def _copy_src(self, level):
        setfscreatecon(self.filecon(level))
        copy(self._src_path, join(self._tempdir, self._filename))
        setfscreatecon(None)

    def copy(self, src):
        setfscreatecon(self.filecon(self.RUN_LEVEL))
        copy(src, join(self._tempdir, basename(src)))
        setfscreatecon(None)

    def open(self, filename, mode):
        filecon = self.filecon(self.RUN_LEVEL)
        setfscreatecon(filecon)
        f = open(filename, mode)
        setfscreatecon(None)

        if filename != '/dev/null' and all([(m not in mode) for m in 'wa+']):
            if check_category(filecon, fgetfilecon(f.fileno())[1]):
                fsetfilecon(f.fileno(), filecon)

        return f

    @property
    def run_env(self):
        return {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        rmtree(self._tempdir)

    def _spawn(self, stdin, stdout, stderr,
               time_limit=None, rss_limit=None, vm_limit=None):
        setexeccon(self.execcon(self.RUN_LEVEL))

        p = PTracedProcess(
            self.run_args,
            executable=self.EXECUTABLE_PATH,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            cwd=self._tempdir,
            env=self.run_env,
            time_limit=time_limit,
            rss_limit=rss_limit,
            vm_limit=vm_limit)

        setexeccon(None)
        return p

    def compile(self, *args):
        raise NotImplementedError

    def run(self, stdin, stdout,
            time_limit=None, rss_limit=None, vm_limit=None):
        stderr = open("/dev/null", "w")
        files = [stdin, stderr]
        compare = None

        if 'w' in stdout.mode:
            files.append(stdout)
        else:
            compare = stdout
            stdout = PIPE

        with nested(*files):
            p = self._spawn(
                stdin=stdin, stdout=stdout, stderr=stderr,
                time_limit=time_limit, rss_limit=rss_limit, vm_limit=vm_limit)

        p.communicate(compare_stdout=compare)
        return p.verdict, p.returncode, p.cputime, p.maxrss, p.maxvm

    def debug(self, stdin, time_limit=None, rss_limit=None, vm_limit=None):
        with stdin:
            p = self._spawn(
                stdin=stdin, stdout=PIPE, stderr=PIPE,
                time_limit=time_limit, rss_limit=rss_limit, vm_limit=vm_limit)

        stdout, stderr = p.communicate()
        return (p.verdict, p.returncode,
                p.cputime, p.maxrss, p.maxvm,
                stdout, stderr)


class CompilerMixin(object):

    def _compile(self, args, executable, env):
        self._copy_src(self.COMPILE_LEVEL)

        with open("/dev/null", "r") as stdin:
            setfscreatecon(self.filecon(self.COMPILE_LEVEL))
            setexeccon(self.execcon(self.COMPILE_LEVEL))
            p = Popen(
                args, bufsize=-1, executable=executable,
                stdin=stdin, stdout=PIPE, stderr=STDOUT,
                close_fds=True, cwd=self._tempdir, env=env)
            setexeccon(None)
            setfscreatecon(None)

        stdout, _ = p.communicate()
        code = p.wait()

        setfilecon(self._tempdir, self.filecon(self.RUN_LEVEL))

        if code != EX_OK:
            return (code, stdout)

        setfilecon(
            join(self._tempdir, self.target_filename),
            self.filecon(self.RUN_LEVEL))

        return (code,)

    def compile(self, args):
        PATH = os.environ["PATH"]

        return self._compile(
            [self.COMPILER] + args + [self._filename],
            which(self.COMPILER, PATH),
            {'TMPDIR': self._tempdir,
             'PATH': PATH})


class BinaryMixin(CompilerMixin):
    EXECUTABLE_PATH = 'a.out'

    @property
    def target_filename(self):
        return self.EXECUTABLE_PATH

    @property
    def run_args(self):
        return [self.EXECUTABLE_PATH]


class BytecodeMixin(CompilerMixin):

    @property
    def target_filename(self):
        return splitext(self._filename)[0] + self.BYTECODE_EXT


class ScriptMixin(object):

    def compile(self, args):
        self._copy_src(self.RUN_LEVEL)
        setfilecon(self._tempdir, self.filecon(self.RUN_LEVEL))
        return (EX_OK,)
