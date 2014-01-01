from os import EX_OK
from os.path import exists
from shlex import split
import sys

from .verdict import AC, CE, SE, verdicttext


class Judge(object):

    def __init__(self, runners, langs,
                 time_grace_factor=5.0, rss_grace_factor=5, vm_grace_factor=5,
                 time_limit=None, rss_limit=None, vm_limit=None):
        self._runners = runners
        self._langs = langs

        self._time_grace_factor = time_grace_factor
        self._rss_grace_factor = rss_grace_factor
        self._vm_grace_factor = vm_grace_factor

        self._time_limit = time_limit
        self._rss_limit = rss_limit
        self._vm_limit = vm_limit

    def _parse_args(self, cmdline):
        args = self._langs.get(cmdline, split(cmdline))

        if args:
            return self._runners.get(args[0], None), args[1:]
        else:
            return (None, None)

    def _run(self, cmdline, src_path, files, limits=None,
             times=1, normalize=False, filename=None):
        Runner, args = self._parse_args(cmdline)

        if Runner is None:
            return SE, -1, 0.0, 0, 0

        input_filename = files[0]
        output_filename = files[1]
        extra_files = files[2:]

        with Runner(src_path, filename) as r:
            result = r.compile(args)

            if result[0] != EX_OK:
                return CE, -1, 0.0, 0, 0, result[1]

            for f in extra_files:
                r.copy(f)

            if limits is not None:
                time_limit, rss_limit, vm_limit = limits
                time_limit, rss_limit, vm_limit = r.adapt_limit(
                    time_limit * self._time_grace_factor,
                    rss_limit * self._rss_grace_factor,
                    vm_limit * self._vm_grace_factor)

                if self._time_limit is not None:
                    time_limit = min(time_limit, self._time_limit)

                if self._rss_limit is not None:
                    rss_limit = min(rss_limit, self._rss_limit)

                if self._vm_limit is not None:
                    vm_limit = min(vm_limit, self._vm_limit)
            else:
                time_limit = self._time_limit
                rss_limit = self._rss_limit
                vm_limit = self._vm_limit

            if output_filename is not None:
                # benchmark only
                if not exists(output_filename):
                    bench_result = r.run(
                        stdin=r.open(input_filename, 'rb'),
                        stdout=r.open(output_filename, 'wb'),
                        time_limit=time_limit,
                        rss_limit=rss_limit,
                        vm_limit=vm_limit)

                    if bench_result[0] != AC:
                        return bench_result

            results = []

            for i in xrange(times):
                result = r.run(
                    stdin=r.open(input_filename, "rb"),
                    stdout=r.open(output_filename, 'rb'),
                    time_limit=time_limit,
                    rss_limit=rss_limit,
                    vm_limit=vm_limit)

                if result[0] != AC:
                    return result

                if normalize:
                    result = result[:2] + r.normalize_usage(*result[2:])

                results.append(result)

            return results

    def benchmark(self, cmdline, src_path, files,
                  times=1, filename=None):
        results = self._run(
            cmdline, src_path, files,
            times=times, normalize=True, filename=filename)

        if not isinstance(results, list):
            if results[0] == CE:
                print >>sys.stderr, results[5]
                raise Exception("Compilation Error")

            raise Exception(
                "%s: exitcode %d, cputime: %f, rss: %d, vm: %d" % (
                    verdicttext[results[0]],
                    results[1], results[2], results[3], results[4]))

        cputime, rss, vm = map(sum, zip(*(r[2:] for r in results)))
        return cputime/times, rss/times, vm/times

    def judge(self, cmdline, src_path, files, error_file,
              time_limit, rss_limit, vm_limit, filename=None):
        results = self._run(
            cmdline, src_path, files,
            (time_limit, rss_limit, vm_limit),
            1, False, filename)

        if not isinstance(results, list):
            if results[0] == CE:
                if isinstance(error_file, str):
                    with open(error_file, 'wb') as f:
                        f.write(results[5])
                else:
                    error_file.write(results[5])
                return results[:-1]
            return results

        return results[0]
