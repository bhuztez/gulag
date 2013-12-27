try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
from ctypes import sizeof
from errno import EINTR, ENOSYS
from fcntl import fcntl, F_GETFL, F_SETFL
from os import (
    close, read, wait4, waitpid,
    O_NONBLOCK, SEEK_END, WUNTRACED, WIFSTOPPED, WSTOPSIG, WNOHANG)
from resource import setrlimit, RLIMIT_CPU, RLIMIT_NPROC, RLIMIT_RSS
import select
from signal import SIGCHLD, SIGTRAP
from subprocess import Popen

from .verdict import AC, WA, RE, TL, ML, RF
from .compat import (
    sigset_t, sigemptyset, sigaddset,
    SIG_BLOCK, SIG_SETMASK, sigprocmask,
    signalfd, signalfd_siginfo,
    traceme, trap_syscall, RESTRICTED_SYSCALLS, MMAP_SYSCALLS,
    get_syscall_number, get_syscall_result, allow_syscall)


class PTracedProcess(Popen):

    def __init__(self, args, executable=None,
                 stdin=None, stdout=None, stderr=None,
                 cwd=None, env={},
                 time_limit=None, rss_limit=None, vm_limit=None):
        self._time_limit = time_limit
        self._rss_limit = rss_limit
        self._vm_limit = vm_limit

        self.cputime = None
        self.maxrss = 0
        self.maxvm = 0
        self.verdict = None

        Popen.__init__(
            self, args, bufsize=-1, executable=executable,
            stdin=stdin, stdout=stdout, stderr=stderr, close_fds=True,
            preexec_fn=self._preexec_hook, cwd=cwd, env=env)

        _, status = waitpid(self.pid, WUNTRACED)

        assert WIFSTOPPED(status), "cannot start subprocess"

        if WSTOPSIG(status) != SIGTRAP:
            self.kill()
            self.wait()
            assert False, "subprocess stopped unexpectedly"

    def _preexec_hook(self):
        setrlimit(RLIMIT_NPROC, (0, 0))

        if self._time_limit is not None:
            setrlimit(
                RLIMIT_CPU,
                (self._time_limit, self._time_limit+0.1))

        if self._rss_limit is not None:
            setrlimit(
                RLIMIT_RSS,
                (self._rss_limit, self._rss_limit+10))

        traceme()

    def statm(self):
        with open("/proc/%d/statm" % self.pid, "r") as f:
            return f.read().split(" ")

    def _on_sigchld(self, fd):
        read(fd, sizeof(signalfd_siginfo))

        pid, status, usage = wait4(self.pid, (WUNTRACED | WNOHANG))
        assert pid != 0

        if not WIFSTOPPED(status):
            self._handle_exitstatus(status)
            self.cputime = usage.ru_utime + usage.ru_stime
            return True

        if WSTOPSIG(status) != SIGTRAP:
            if self.verdict is None:
                self.verdict = RE
            self.kill()
            return True

        num = get_syscall_number(self.pid)

        if num in RESTRICTED_SYSCALLS:
            if not allow_syscall(self.pid, num):
                if self.verdict is None:
                    self.verdict = RF
                self.kill()
                return True

        elif num in MMAP_SYSCALLS:
            ret = get_syscall_result(self.pid)

            if ret != -ENOSYS:
                statm = self.statm()

                self.maxvm = max(self.maxvm, int(statm[0]))
                self.maxrss = max(self.maxrss, int(statm[1]))

                if self._vm_limit and self.maxvm > self._vm_limit:
                    if self.verdict is None:
                        self.verdict = ML
                    self.kill()
                    return True

        trap_syscall(self.pid)

    def _read_pipe(self, fd, buf):
        data = read(fd, 4096)
        if not data:
            return True
        buf.write(data)

    def _compare_stdout(self, fd, compare):
        data = read(fd, 4096)

        if not data:
            cur = compare.tell()
            compare.seek(0, SEEK_END)
            end = compare.tell()
            if cur != end:
                if self.verdict is None:
                    self.verdict = WA
            return True

        expected = compare.read(len(data))
        if data != expected:
            if self.verdict is None:
                self.verdict = WA
            self.kill()
            return True

    def communicate(self, compare_stdout=None):
        mask = sigset_t()
        oldmask = sigset_t()
        sigemptyset(mask)
        sigemptyset(oldmask)
        sigaddset(mask, SIGCHLD)
        sigprocmask(SIG_BLOCK, mask, oldmask)

        sfd = signalfd(-1, mask, 0)
        fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL) | O_NONBLOCK)

        fd_callbacks = {}
        fd_callbacks[sfd] = (self._on_sigchld,)

        if self.stdout is not None:
            if compare_stdout:
                stdout = None
                fd_callbacks[self.stdout.fileno()] = (
                    self._compare_stdout, compare_stdout)
            else:
                stdout = StringIO()
                fd_callbacks[self.stdout.fileno()] = (
                    self._read_pipe, stdout)
        else:
            stdout = None

        if self.stderr is not None:
            stderr = StringIO()
            fd_callbacks[self.stderr.fileno()] = (
                self._read_pipe, stderr)
        else:
            stderr = None

        registered = 0
        poller = select.poll()

        for fd in fd_callbacks:
            poller.register(
                fd, (select.POLLIN | select.POLLPRI | select.POLLHUP))
            registered += 1

        trap_syscall(self.pid)

        if self._time_limit is None:
            timeout = None
        else:
            timeout = self._time_limit + 1.0

        while registered:
            try:
                ready = poller.poll(timeout * 1000)
            except select.error as e:
                if e.args[0] == EINTR:
                    continue

                self.kill()
                raise

            if not ready:
                if self.verdict is None:
                    self.verdict = TL
                self.kill()
                continue

            for fd, _mode in ready:
                callback = fd_callbacks.get(fd, None)

                if callback is not None:
                    unregister = callback[0](fd, *callback[1:])

                    if unregister:
                        poller.unregister(fd)
                        registered -= 1

        if self.verdict is None:
            self.verdict = AC if self.returncode == 0 else RE

            if self._time_limit is not None:
                if self.cputime > self._time_limit:
                    self.verdict = TL

            if self.verdict == RE:
                if self._rss_limit is not None:
                    if self.maxrss > self._rss_limit:
                        self.verdict = ML

        close(sfd)
        sigprocmask(SIG_SETMASK, oldmask, None)

        if self.stdout is not None:
            self.stdout.close()

        if self.stderr is not None:
            self.stderr.close()

        if stdout is not None:
            stdout = stdout.getvalue()

        if stderr is not None:
            stderr = stderr.getvalue()

        return (stdout, stderr)
