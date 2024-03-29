#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import cProfile
import inspect
import os as pyos

from test_elf import *
from test_macho import *
from test_shellcode import *

perf_res_dir = "./perf_results/"
test_mapping = []


def populate_tests():
    global test_mapping

    unit_tests = [ELFTest(), MACHOTest(), TestShellcode()]

    for ut in unit_tests:
        ut_functions = inspect.getmembers(ut, predicate=inspect.ismethod)

        for test_name, test_fn in ut_functions:
            if not test_name.startswith("test_"):
                continue

            outfile = perf_res_dir + test_name + ".perf"
            test_mapping.append((test_fn, outfile))


def ql_profile(run_fn, outfile):
    pr = cProfile.Profile()
    pr.enable()
    run_fn()
    pr.disable()
    pr.dump_stats(outfile)
    pr.print_stats()


def profile_all_functions():
    if not pyos.path.isdir("perf_results"):
        pyos.mkdir("perf_results")

    populate_tests()

    for tm_func, rm_outfile in test_mapping:
        try:
            ql_profile(tm_func, rm_outfile)
        except:
            pass


if __name__ == "__main__":
    profile_all_functions()
