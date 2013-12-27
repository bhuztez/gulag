import os
import os.path
import stat


def which(name, PATH=None):
    if PATH is None:
        PATH = os.environ['PATH']

    for path in PATH.split(':'):
        fullname = os.path.join(path, name)

        try:
            mode = os.stat(fullname).st_mode
            if not stat.S_ISREG(mode):
                continue

            if not (mode & stat.S_IXOTH):
                continue

            return fullname
        except OSError:
            continue
