import platform

from ctypes import (
    cdll, sizeof, POINTER, Structure,
    c_short, c_ulong, c_long, c_int, c_void_p,
    c_uint8, c_int32, c_uint32, c_uint64)
from ctypes.util import find_library
from os import O_CREAT, O_RDWR, O_WRONLY


libc = cdll.LoadLibrary(find_library('c'))


class signalfd_siginfo(Structure):
    _fields_ = (
        ('ssi_signo',   c_uint32),
        ('ssi_errno',   c_int32),
        ('ssi_code',    c_int32),
        ('ssi_pid',     c_uint32),
        ('ssi_uid',     c_uint32),
        ('ssi_fd',      c_int32),
        ('ssi_tid',     c_uint32),
        ('ssi_band',    c_uint32),
        ('ssi_overrun', c_uint32),
        ('ssi_trapno',  c_uint32),
        ('ssi_status',  c_int32),
        ('ssi_int',     c_int32),
        ('ssi_ptr',     c_uint64),
        ('ssi_utime',   c_uint64),
        ('ssi_stime',   c_uint64),
        ('ssi_addr',    c_uint64),
        ('_padding',    c_uint8 * 48))

SIG_BLOCK = 0
SIG_UNBLOCK = 1
SIG_SETMASK = 2

_SIGSET_NWORDS = 1024 / (8 * sizeof(c_ulong))
sigset_t = c_ulong * _SIGSET_NWORDS

sigemptyset = libc.sigemptyset
sigemptyset.argtypes = [POINTER(sigset_t)]
sigemptyset.restype = c_int

sigaddset = libc.sigaddset
sigaddset.argtypes = [POINTER(sigset_t), c_int]
sigaddset.restype = c_int

sigprocmask = libc.sigprocmask
sigprocmask.argtypes = [c_int, POINTER(sigset_t), POINTER(sigset_t)]
sigprocmask.restype = c_int

signalfd = libc.signalfd
signalfd.argtypes = [c_int, POINTER(sigset_t), c_int]
signalfd.restype = c_int

ptrace = libc.ptrace
ptrace.argtypes = [c_short, c_int, c_int, c_void_p]
ptrace.restype = c_long

PTRACE_TRACEME = 0
PTRACE_PEEKUSER = 3
PTRACE_SYSCALL = 24


def traceme():
    return ptrace(PTRACE_TRACEME, 0, 0, None)


def trap_syscall(pid):
    return ptrace(PTRACE_SYSCALL, pid, 0, None)


machine = platform.machine()

if machine == 'x86_64':
    # RAX = syscall(ORIG_RAX, RDI, RSI, RDX, RCX, ...)
    RAX = 10
    RCX = 11
    RDX = 12
    RSI = 13
    RDI = 14
    ORIG_RAX = 15

    SYS_open = 2
    SYS_socket = 41
    SYS_creat = 85
    SYS_openat = 257

    SYS_mmap = 9
    SYS_munmap = 11
    SYS_brk = 12
    SYS_mremap = 25
    SYS_remap_file_pages = 216

    RESTRICTED_SYSCALLS = [
        SYS_open, SYS_socket, SYS_creat, SYS_openat]
    MMAP_SYSCALLS = [
        SYS_mmap, SYS_munmap, SYS_brk, SYS_mremap, SYS_remap_file_pages]

    def get_syscall_number(pid):
        return ptrace(PTRACE_PEEKUSER, pid, 8 * ORIG_RAX, None)

    def get_syscall_result(pid):
        return ptrace(PTRACE_PEEKUSER, pid, 8 * RAX, None)

    def allow_syscall(pid, num):
        if num == SYS_open:
            flags = ptrace(PTRACE_PEEKUSER, pid, 8 * RSI, None)
        elif num == SYS_openat:
            flags = ptrace(PTRACE_PEEKUSER, pid, 8 * RDX, None)
        else:
            return False

        return not (flags & (O_WRONLY | O_RDWR | O_CREAT))

else:
    raise NotImplementedError
