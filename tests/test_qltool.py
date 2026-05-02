#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
import subprocess
import re
import sys
import unittest


class Qltool_Test(unittest.TestCase):
    def __run(self, cmdline: str) -> bytes:
        try:
            output = subprocess.check_output([sys.executable] + cmdline.split(), stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"command '{e.cmd}' return with error (code {e.returncode}): {e.output}")
        else:
            return output

    def test_qltool_exec_args(self):
        output = self.__run(r'../qltool run -f ../examples/rootfs/x8664_linux/bin/x8664_args --rootfs ../examples/rootfs/x8664_linux --verbose off --args test1 test2 test3')

        self.assertEqual(b'arg        2 test3', output.splitlines()[-1])

    def test_qltool_shellcode(self):
        self.__run(r'../qltool code --os linux --arch x86 --format asm -f ../examples/shellcodes/lin32_execve.asm')

    def test_qltool_coverage(self):
        os.makedirs(r'./log_test', exist_ok=True)

        self.__run(r'../qltool run -f ../examples/rootfs/x8664_efi/bin/TcgPlatformSetupPolicy --rootfs ../examples/rootfs/x8664_efi --coverage-format drcov --coverage-file log_test/TcgPlatformSetupPolicy')

    def test_qltool_json(self):
        self.__run(r'../qltool run -f ../examples/rootfs/x86_linux/bin/x86_hello --rootfs ../examples/rootfs/x86_linux --verbose off --json')

    def test_qltool_filter(self):
        filter_pattern = r'^(open|brk)'
        output = self.__run(fr'../qltool run -f ../examples/rootfs/arm_linux/bin/arm_hello --rootfs ../examples/rootfs/arm_linux -e {filter_pattern} --log-plain')

        # keep only log entries and strip them from log prefix
        p = re.compile(rb'^\[\S\]\s+')
        log_entries = (p.sub(b'', line) for line in output.splitlines() if p.match(line))

        # make sure that all log entries are of the expected regex filter pattern
        p = re.compile(filter_pattern.encode())
        self.assertTrue(all(p.search(entry) is not None for entry in log_entries))


if __name__ == "__main__":
    unittest.main()
