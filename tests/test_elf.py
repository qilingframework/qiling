#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import unittest
import string
import random
import os
import io
import re

import sys
sys.path.append("..")

from typing import Any, Sequence

from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_INTERCEPT, QL_STOP, QL_VERBOSE
from qiling.exception import *
from qiling.extensions import pipe
from qiling.os.const import STRING
from qiling.os.posix import syscall
from qiling.os.mapper import QlFsMappedObject


class ELFTest(unittest.TestCase):

    def test_libpatch_elf_linux_x8664(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/patch_test.bin"], "../examples/rootfs/x8664_linux")
        ql.patch(0x0000000000000575, b'qiling\x00', target='libpatch_test.so')
        ql.run()
        del ql

    def test_elf_freebsd_x8664(self):
        ql = Qiling(["../examples/rootfs/x8664_freebsd/bin/x8664_hello_asm"], "../examples/rootfs/x8664_freebsd", verbose=QL_VERBOSE.DUMP)
        ql.run()
        del ql

    def test_elf_partial_linux_x8664(self):
        snapshot_file = r'/tmp/snapshot.bin'

        def dump(ql: Qiling, *args, **kw):
            ql.save(reg=False, cpu_context=True, snapshot=snapshot_file)
            ql.emu_stop()

        ql = Qiling(["../examples/rootfs/x8664_linux/bin/sleep_hello"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEFAULT)
        load_address = ql.profile.getint("OS64", "load_address")
        ql.hook_address(dump, load_address + 0x1094)
        ql.run()

        ql = Qiling(["../examples/rootfs/x8664_linux/bin/sleep_hello"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
        load_address = ql.profile.getint("OS64", "load_address")
        ql.restore(snapshot=snapshot_file)

        begin_point = load_address + 0x109e
        end_point = load_address + 0x10bc

        ql.run(begin_point, end_point)

        del ql

    def test_elf_x_only_segment(self):
        def stop(ql: Qiling):
            ql.emu_stop()

        ql = Qiling(["../examples/rootfs/x8664_linux/bin/sleep_hello_with_x_only_segment"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
        load_address = ql.profile.getint("OS64", "load_address")
        ql.hook_address(stop, load_address + 0x1094)
        ql.run()

        del ql

    def _test_elf_linux_x86_snapshot_restore_common(self, reg=False, ctx=False):
        rootfs = "../examples/rootfs/x86_linux"
        cmdline = ["../examples/rootfs/x86_linux/bin/x86_hello"]
        snapshot = os.path.join(rootfs, 'snapshot_restore_reg_ctx.snapshot')

        ql = Qiling(cmdline, rootfs, verbose=QL_VERBOSE.DEBUG)

        load_address = ql.profile.getint("OS32", "load_address")
        hook_address = load_address + 0x542  # call printf

        def dump(ql: Qiling):
            ql.save(reg=reg, cpu_context=ctx, os=True, loader=True, snapshot=snapshot)
            ql.emu_stop()

        ql.hook_address(dump, hook_address)
        ql.run()

        # make sure that the ending PC is the same as the hook address because dump stops the emulater
        self.assertEqual(ql.arch.regs.arch_pc, hook_address)
        del ql

        ql = Qiling(cmdline, rootfs, verbose=QL_VERBOSE.DEBUG)
        ql.restore(snapshot=snapshot)

        # ensure that the starting PC is same as the PC we stopped on when taking the snapshot
        self.assertEqual(ql.arch.regs.arch_pc, hook_address)

        ql.run(begin=hook_address)
        del ql

        os.remove(snapshot)

    def test_elf_linux_x86_snapshot_restore_reg(self):
        self._test_elf_linux_x86_snapshot_restore_common(reg=True, ctx=False)

    def test_elf_linux_x86_snapshot_restore_ctx(self):
        self._test_elf_linux_x86_snapshot_restore_common(reg=False, ctx=True)

    def test_elf_linux_x86_snapshot_restore_reg_ctx(self):
        self._test_elf_linux_x86_snapshot_restore_common(reg=True, ctx=True)

    PARAMS_PUTS = {'s': STRING}

    def test_elf_linux_x8664(self):
        checklist = {}

        def my_puts(ql: Qiling):
            params = ql.os.resolve_fcall_params(ELFTest.PARAMS_PUTS)
            print(f'puts("{params["s"]}")')

            reg = ql.arch.regs.rax
            print(f'reg : {reg:#x}')

            checklist['set_api'] = reg

        def write_onEnter(ql: Qiling, fd: int, str_ptr: int, str_len: int):
            checklist['set_syscall_onenter'] = True
            print("enter write syscall!")

            # override syscall pc (ignored) and set of params with our own
            return None, (fd, str_ptr + 1, str_len - 1)

        def write_onexit(ql: Qiling, fd: int, str_ptr: int, str_len: int, retval: int):
            checklist['set_syscall_onexit'] = True
            print("exit write syscall!")

            # override syscall return value with our own
            return str_len + 1

        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_args", "1234test", "12345678", "bin/x8664_hello"],  "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)

        ql.os.set_syscall(1, write_onEnter, QL_INTERCEPT.ENTER)
        ql.os.set_syscall(1, write_onexit, QL_INTERCEPT.EXIT)
        ql.os.set_api('puts', my_puts)

        blob = bytes.fromhex("ff fe fd fc fb fa fb fc fc fe fd")

        ql.mem.map(0x1000, 0x1000)
        ql.mem.write(0x1000, blob)

        ql.mem.map(0x2000, 0x1000)
        ql.mem.write(0x2000, blob)

        ql.run()

        self.assertListEqual([0x1000, 0x2000], ql.mem.search(blob))
        self.assertEqual(0x5555555546ca, checklist['set_api'])
        self.assertTrue(checklist['set_syscall_onenter'])
        self.assertTrue(checklist['set_syscall_onexit'])

        del ql

    def test_elf_hijackapi_linux_x8664(self):
        checklist = {}

        def my_puts_enter(ql: Qiling):
            params = ql.os.resolve_fcall_params(ELFTest.PARAMS_PUTS)
            checklist['enter_str'] = params["s"]

        def my_puts_exit(ql):
            checklist['exit_rdi'] = ql.arch.regs.rdi

        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_puts"],  "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
        ql.os.set_api('puts', my_puts_enter, QL_INTERCEPT.ENTER)
        ql.os.set_api('puts', my_puts_exit, QL_INTERCEPT.EXIT)

        ql.run()

        self.assertIn(checklist['exit_rdi'], (0x1, 0x7fffb81c2760))
        self.assertEqual("CCCC", checklist['enter_str'])

        del ql

    def test_elf_linux_x8664_flex_api(self):
        opened = []

        def onenter_fopen(ql: Qiling):
            params = ql.os.resolve_fcall_params({
                'filename' : STRING,
                'mode'     : STRING
            })

            # log opened filenames
            opened.append(params['filename'])

        def hook_main(ql: Qiling):
            # set up fopen hook when reaching main
            ql.os.set_api('fopen', onenter_fopen, QL_INTERCEPT.ENTER)

        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_fetch_urandom"],  "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEFAULT)

        ba = ql.loader.images[0].base
        ql.hook_address(hook_main, ba + 0x10e0)
        ql.run()
        del ql

        # test whether we interpected opening urandom
        self.assertListEqual(opened, [r'/dev/urandom'])

    def test_elf_linux_x8664_static(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_hello_static"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
        ql.run()
        del ql

    def test_elf_linux_x86(self):
        filename = 'test.qlog'

        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_hello"], "../examples/rootfs/x86_linux", verbose=QL_VERBOSE.DEBUG, log_devices=[filename])
        ql.run()

        os.remove(filename)
        del ql

    def test_elf_linux_x86_static(self):
        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_hello_static"], "../examples/rootfs/x86_linux", verbose=QL_VERBOSE.DEBUG)
        ql.run()
        del ql

    def posix_syscall_test(self, argv: str, rootfs: str, syscalls: Sequence[str]):
        """A generic method to test out POSIX system calls hooking.
        """

        checklist = []

        def test_syscall_read(ql: Qiling, fd: int, buf: int, count: int):
            retval = syscall.ql_syscall_read(ql, fd, buf, count)

            hpath = ql.os.fd[fd].name

            if os.path.basename(hpath) == "test_syscall_read.txt":
                mcontent = ql.mem.read(buf, count)

                with open(hpath, 'rb') as infile:
                    fcontent = infile.read()

                if ql.host.os is not QL_OS.WINDOWS:
                    os.remove(hpath)

                self.assertEqual(mcontent, fcontent)
                checklist.append('read')

            return retval

        def test_syscall_write(ql: Qiling, fd: int, buf: int, count: int):
            retval = syscall.ql_syscall_write(ql, fd, buf, count)

            hpath = ql.os.fd[fd].name

            if os.path.basename(hpath) == "test_syscall_write.txt":
                mcontent = ql.mem.read(buf, count)

                with open(hpath, 'rb') as infile:
                    fcontent = infile.read()

                if ql.host.os is not QL_OS.WINDOWS:
                    os.remove(hpath)

                self.assertEqual(mcontent, fcontent)
                checklist.append('write')

            return retval

        def test_syscall_open(ql: Qiling, path: int, flags: int, mode: int):
            retval = syscall.ql_syscall_open(ql, path, flags, mode)

            vpath = ql.os.utils.read_cstring(path)

            if vpath == "test_syscall_open.txt":
                hpath = ql.os.path.virtual_to_host_path(vpath)

                self.assertTrue(os.path.isfile(hpath))
                checklist.append('open')

                if ql.host.os is not QL_OS.WINDOWS:
                    os.remove(hpath)

            return retval

        def test_syscall_openat(ql: Qiling, fd: int, path: int, flags: int, mode: int):
            retval = syscall.ql_syscall_openat(ql, fd, path, flags, mode)

            vpath = ql.os.utils.read_cstring(path)

            if vpath == "test_syscall_open.txt":
                hpath = ql.os.path.virtual_to_host_path(vpath)

                self.assertTrue(os.path.isfile(hpath))
                checklist.append('openat')

                if ql.host.os is not QL_OS.WINDOWS:
                    os.remove(hpath)

            return retval

        def test_syscall_unlink(ql: Qiling, path: int):
            retval = syscall.ql_syscall_unlink(ql, path)

            vpath = ql.os.utils.read_cstring(path)

            if vpath == "test_syscall_unlink.txt":
                hpath = ql.os.path.virtual_to_host_path(vpath)

                self.assertFalse(os.path.isfile(hpath))
                checklist.append('unlink')

            return retval

        def test_syscall_unlinkat(ql: Qiling, fd: int, path: int, flags: int):
            retval = syscall.ql_syscall_unlinkat(ql, fd, path, flags)

            vpath = ql.os.utils.read_cstring(path)

            if vpath == "test_syscall_unlink.txt":
                hpath = ql.os.path.virtual_to_host_path(vpath)

                self.assertFalse(os.path.isfile(hpath))
                checklist.append('unlinkat')

            return retval

        def test_syscall_truncate(ql: Qiling, path: int, length: int):
            retval = syscall.ql_syscall_truncate(ql, path, length)

            vpath = ql.os.utils.read_cstring(path)

            if vpath == "test_syscall_truncate.txt":
                hpath = ql.os.path.virtual_to_host_path(vpath)

                self.assertEqual(length, os.stat(hpath).st_size)
                checklist.append('truncate')

                if ql.host.os is not QL_OS.WINDOWS:
                    os.remove(hpath)

            return retval

        def test_syscall_ftruncate(ql: Qiling, fd: int, length: int):
            retval = syscall.ql_syscall_ftruncate(ql, fd, length)

            hpath = ql.os.fd[fd].name

            if os.path.basename(hpath) == "test_syscall_ftruncate.txt":
                self.assertEqual(length, os.stat(hpath).st_size)
                checklist.append('ftruncate')

                if ql.host.os is not QL_OS.WINDOWS:
                    os.remove(hpath)

            return retval

        hooks = {
            'read'      : test_syscall_read,
            'write'     : test_syscall_write,
            'open'      : test_syscall_open,
            'openat'    : test_syscall_openat,
            'unlink'    : test_syscall_unlink,
            'unlinkat'  : test_syscall_unlinkat,
            'truncate'  : test_syscall_truncate,
            'ftruncate' : test_syscall_ftruncate,
        }

        ql = Qiling([f'{rootfs}{argv}'], rootfs, verbose=QL_VERBOSE.DEBUG)

        # hook reuested system calls
        for name in syscalls:
            ql.os.set_syscall(name, hooks[name])

        ql.run()

        # make sure we visited them all
        self.assertSequenceEqual(syscalls, checklist)

    def test_elf_linux_x86_posix_syscall(self):
        syscalls = ['openat', 'write', 'read', 'truncate', 'ftruncate', 'unlink']

        self.posix_syscall_test(r'/bin/x86_posix_syscall', r'../examples/rootfs/x86_linux', syscalls)

    def test_elf_linux_arm(self):
        def my_puts(ql: Qiling):
            params = ql.os.resolve_fcall_params(ELFTest.PARAMS_PUTS)
            print(f'puts("{params["s"]}")')

            all_mem = ql.mem.save()
            ql.mem.restore(all_mem)

        ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_hello"], "../examples/rootfs/arm_linux", verbose=QL_VERBOSE.DEBUG)
        ql.os.set_api('puts', my_puts)
        ql.run()
        del ql

    def test_elf_linux_arm_static(self):
        ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_hello_static"], "../examples/rootfs/arm_linux", verbose=QL_VERBOSE.DEFAULT)
        all_mem = ql.mem.save()
        ql.mem.restore(all_mem)
        ql.run()
        del ql

    @unittest.skip('broken: ARM executable should be generated properly')
    def test_elf_linux_arm_posix_syscall(self):
        # TODO: check the list, it might be inacurate
        syscalls = ['openat', 'write', 'read', 'truncate', 'ftruncate', 'unlink']

        self.posix_syscall_test(r'/bin/arm_posix_syscall', r'../examples/rootfs/arm_linux', syscalls)

    def test_elf_linux_arm64(self):
        ql = Qiling(["../examples/rootfs/arm64_linux/bin/arm64_hello"], "../examples/rootfs/arm64_linux", verbose=QL_VERBOSE.DEBUG)
        ql.run()
        del ql

    def test_elf_linux_arm64_static(self):
        ql = Qiling(["../examples/rootfs/arm64_linux/bin/arm64_hello_static"], "../examples/rootfs/arm64_linux", verbose=QL_VERBOSE.DEFAULT)
        ql.run()
        del ql

    def test_elf_linux_mips32eb_static(self):
        ql = Qiling(["../examples/rootfs/mips32_linux/bin/mips32_hello_static"], "../examples/rootfs/mips32_linux")
        ql.run()
        del ql

    @staticmethod
    def random_generator(length: int):
        chars = string.ascii_uppercase + string.digits

        return ''.join(random.choices(chars, k=length))

    def test_elf_linux_mips32eb(self):
        ql = Qiling(["../examples/rootfs/mips32_linux/bin/mips32_hello", self.random_generator(64)], "../examples/rootfs/mips32_linux")
        ql.run()

        del ql

    def test_mips32eb_fake_urandom(self):
        class Fake_urandom(QlFsMappedObject):
            def read(self, size: int):
                return b'\x01' * size

            def fstat(self):
                return -1

            def close(self):
                return 0

        ql = Qiling(["../examples/rootfs/mips32_linux/bin/mips32_fetch_urandom"],  "../examples/rootfs/mips32_linux")
        ql.add_fs_mapper("/dev/urandom", Fake_urandom())

        ql.run()
        del ql

    def test_elf_onEnter_mips32el(self):
        def my_puts_onenter(ql: Qiling):
            params = ql.os.resolve_fcall_params(ELFTest.PARAMS_PUTS)
            print(f'puts("{params["s"]}")')

            params = ql.os.fcall.readParams(ELFTest.PARAMS_PUTS.values())
            self.my_puts_onenter_addr = params[0]

            return 2

        ql = Qiling(["../examples/rootfs/mips32el_linux/bin/mips32el_double_hello"], "../examples/rootfs/mips32el_linux")
        ql.os.set_api('puts', my_puts_onenter, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertEqual(4196680, self.my_puts_onenter_addr)

        del ql

    def test_elf_linux_arm64_posix_syscall(self):
        syscalls = ['openat', 'write', 'read', 'truncate', 'ftruncate', 'unlinkat']

        self.posix_syscall_test(r'/bin/arm64_posix_syscall', r'../examples/rootfs/arm64_linux', syscalls)

    def test_elf_linux_mips32el(self):
        ql = Qiling(["../examples/rootfs/mips32el_linux/bin/mips32el_hello", self.random_generator(64)], "../examples/rootfs/mips32el_linux")
        ql.run()
        del ql

    def test_elf_linux_mips32el_static(self):
        ql = Qiling(["../examples/rootfs/mips32el_linux/bin/mips32el_hello_static", self.random_generator(64)], "../examples/rootfs/mips32el_linux")
        ql.run()
        del ql

    def test_elf_linux_mips32el_posix_syscall(self):
        syscalls = ['open', 'write', 'read', 'truncate', 'ftruncate', 'unlink']

        self.posix_syscall_test(r'/bin/mips32el_posix_syscall', r'../examples/rootfs/mips32el_linux', syscalls)

    def test_elf_linux_powerpc(self):
        ql = Qiling(["../examples/rootfs/powerpc_linux/bin/powerpc_hello"], "../examples/rootfs/powerpc_linux", verbose=QL_VERBOSE.DEBUG)
        ql.run()
        del ql

    def test_elf_linux_arm_custom_syscall(self):
        checklist = {}

        def my_syscall_write(ql: Qiling, fd: int, buf: int, count: int):
            try:
                data = ql.mem.read(buf, count)
                ql.os.fd[fd].write(data)
            except:
                regreturn = -1
            else:
                regreturn = count

            checklist['set_syscall'] = ql.arch.regs.r0

            return regreturn

        ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_hello"], "../examples/rootfs/arm_linux")
        ql.os.set_syscall('write', my_syscall_write)
        ql.run()

        self.assertEqual(1, checklist['set_syscall'])

        del ql

    def test_elf_linux_x86_crackme(self):
        def instruction_count(ql: Qiling, address: int, size: int, user_data: Any):
            user_data[0] += 1

        def my__llseek(ql, *args, **kw):
            pass

        def run_one_round(payload):
            ql = Qiling(["../examples/rootfs/x86_linux/bin/crackme_linux"], "../examples/rootfs/x86_linux", console=False)

            ins_count = [0]
            ql.hook_code(instruction_count, ins_count)
            ql.os.set_syscall("_llseek", my__llseek)

            ql.os.stdin = pipe.SimpleInStream(0)
            ql.os.stdin.write(payload)

            ql.run()
            del ql

            return ins_count[0]

        def solve():
            idx_list = [1, 4, 2, 0, 3]

            flag = b'\x00\x00\x00\x00\x00\n'

            old_count = run_one_round(flag)
            for idx in idx_list:
                for i in b'L1NUX\\n':
                    flag = flag[:idx] + chr(i).encode() + flag[idx + 1:]
                    tmp = run_one_round(flag)

                    if tmp > old_count:
                        old_count = tmp
                        break

            print(flag)

        print("Linux Simple Crackme Brute Force, This Will Take Some Time ...")
        solve()

    def test_x86_fake_urandom_multiple_times(self):
        next_id = 0

        def get_next_id() -> int:
            nonlocal next_id

            curr_id = next_id
            next_id += 1

            return curr_id

        ids = []

        class Fake_urandom(QlFsMappedObject):
            def __init__(self):
                ids.append(get_next_id())

            def read(self, size: int):
                return b'\x01' * size

            def fstat(self):
                return -1

            def close(self):
                return 0

        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_fetch_urandom_multiple_times"],  "../examples/rootfs/x86_linux")
        ql.add_fs_mapper("/dev/urandom", Fake_urandom())

        ql.run()

        self.assertListEqual([0], ids)

        del ql

    def test_x86_fake_urandom(self):
        class Fake_urandom(QlFsMappedObject):

            def read(self, size: int):
                return b"\x01" * size

            def fstat(self):
                return -1

            def close(self):
                return 0

        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_fetch_urandom"],  "../examples/rootfs/x86_linux", verbose=QL_VERBOSE.DEBUG)
        ql.add_fs_mapper("/dev/urandom", Fake_urandom())

        ql.run()
        del ql

    def test_x8664_map_urandom(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_fetch_urandom"],  "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
        ql.add_fs_mapper("/dev/urandom", "/dev/urandom")

        ql.run()

        del ql

    def test_x8664_symlink(self):
        ql = Qiling(["../examples/rootfs/x8664_linux_symlink/bin/x8664_hello"], "../examples/rootfs/x8664_linux_symlink", verbose=QL_VERBOSE.DEBUG)
        ql.run()
        del ql

    def test_x8664_absolute_path(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/absolutepath"],  "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)

        ql.os.stdout = pipe.SimpleOutStream(1)
        ql.run()

        self.assertEqual(ql.os.stdout.read(), b'test_complete\n\ntest_complete\n\n')

        del ql

    def test_x8664_getcwd(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/testcwd"],  "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)

        ql.os.stdout = pipe.SimpleOutStream(1)
        ql.run()

        self.assertEqual(ql.os.stdout.read(), b'/\n/lib\n/bin\n/\n')

        del ql

    def test_elf_linux_x86_return_from_main_stackpointer(self):
        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_return_main"],  "../examples/rootfs/x86_linux", stop=QL_STOP.STACK_POINTER)
        ql.run()
        del ql

    def test_elf_linux_x86_return_from_main_exit_trap(self):
        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_return_main"],  "../examples/rootfs/x86_linux", stop=QL_STOP.EXIT_TRAP)
        ql.run()
        del ql

    def test_elf_linux_x8664_return_from_main_stackpointer(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_return_main"],  "../examples/rootfs/x8664_linux", stop=QL_STOP.STACK_POINTER)
        ql.run()
        del ql

    def test_elf_linux_x8664_return_from_main_exit_trap(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_return_main"],  "../examples/rootfs/x8664_linux", stop=QL_STOP.EXIT_TRAP)
        ql.run()
        del ql

    def test_arm_stat64(self):
        ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_stat64", "/bin/arm_stat64"], "../examples/rootfs/arm_linux", verbose=QL_VERBOSE.DEBUG)
        ql.run()
        del ql

    def test_elf_linux_x8664_getdents(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_getdents"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)

        ql.os.stdout = io.BytesIO()
        ql.run()

        ql.os.stdout.seek(0)
        self.assertIn("bin\n", ql.os.stdout.read().decode("utf-8"))

        del ql

    def test_elf_linux_armeb(self):
        ql = Qiling(["../examples/rootfs/armeb_linux/bin/armeb_hello"], "../examples/rootfs/armeb_linux", verbose=QL_VERBOSE.DEBUG)
        ql.run()
        del ql

    def test_elf_linux_armeb_static(self):
        ql = Qiling(["../examples/rootfs/armeb_linux/bin/armeb_hello_static"], "../examples/rootfs/armeb_linux", verbose=QL_VERBOSE.DEFAULT)
        ql.run()
        del ql

    # TODO: Disable for now
    # def test_armoabi_eb_linux_syscall_elf_static(self):
    #     # src: https://github.com/qilingframework/qiling/blob/1f1e9bc756e59a0bfc112d32735f8882b1afc165/examples/src/linux/posix_syscall.c
    #     ql = Qiling(["../examples/rootfs/armeb_linux/bin/posix_syscall_msb.armoabi"], "../examples/rootfs/armeb_linux", verbose=QL_VERBOSE.DEBUG)
    #     ql.run()

    def test_armoabi_le_linux_syscall_elf_static(self):
        # src: https://github.com/qilingframework/qiling/blob/1f1e9bc756e59a0bfc112d32735f8882b1afc165/examples/src/linux/posix_syscall.c
        ql = Qiling(["../examples/rootfs/arm_linux/bin/posix_syscall_lsb.armoabi"], "../examples/rootfs/arm_linux", verbose=QL_VERBOSE.DEBUG)
        ql.run()
        del ql

    def test_elf_linux_x86_getdents64(self):
        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_getdents64"], "../examples/rootfs/x86_linux", verbose=QL_VERBOSE.DEBUG)

        ql.os.stdout = pipe.SimpleOutStream(1)
        ql.run()

        self.assertIn("bin\n", ql.os.stdout.read().decode("utf-8"))

        del ql

    def test_memory_search(self):
        ql = Qiling(code=b"\xCC", archtype=QL_ARCH.X8664, ostype=QL_OS.LINUX, verbose=QL_VERBOSE.DEBUG)

        ql.mem.map(0x1000, 0x1000)
        ql.mem.map(0x2000, 0x1000)
        ql.mem.map(0x3000, 0x1000)

        ql.mem.write(0x1000, b"\x47\x06\x0d\x1e\x0d\x1a\x53\x0f\x07\x06\x06\x09\x53\x0f\x01\x1e\x0d\x53\x11\x07\x1d\x53\x1d\x18\x4f\x53\x06\x0d\x1e\x0d\x1a\x53\x0f\x07\x06\x06\x09\x53\x04\x0d\x1c\x53\x11\x07\x1d\x53\x0c\x07\x1f\x06\x45")
        ql.mem.write(0x2000, b"\x47\x06\x0d\x1e\x0d\x1a\x53\x0f\x07\x06\x06\x09\x53\x1a\x1d\x06\x53\x09\x1a\x07\x1d\x06\x0c\x53\x09\x06\x0c\x53\x0c\x0d\x1b\x0d\x1a\x1c\x53\x11\x07\x1d\x4f\x53\x06\x0d\x1e\x0d\x1a\x53\x0f\x07\x06\x06\x09\x53\x05\x09\x03\x0d\x53\x11\x07\x1d\x53\x0b\x1a\x11\x45")
        ql.mem.write(0x3000, b"\x47\x06\x0d\x1e\x0d\x1a\x53\x0f\x07\x06\x06\x09\x53\x1b\x09\x11\x53\x0f\x07\x07\x0c\x0a\x11\x0d\x4f\x53\x06\x0d\x1e\x0d\x1a\x53\x0f\x07\x06\x06\x09\x53\x1c\x0d\x04\x04\x53\x09\x53\x04\x01\x0d\x53\x09\x06\x0c\x53\x00\x1d\x1a\x1c\x53\x11\x07\x1d\x45")
        ql.mem.write(0x1FFB, b"\x1f\x00\x07\x53\x03\x06\x07\x1f\x1b")

        # Needle not in haystack
        self.assertEqual([], ql.mem.search(b"\x3a\x01\x0b\x03\x53\x29\x1b\x1c\x04\x0d\x11"))

        # Needle appears several times in haystack
        self.assertEqual([0x1000 + 24, 0x2000 + 38, 0x3000 + 24], ql.mem.search(b"\x4f\x53\x06\x0d\x1e\x0d\x1a"))

        # Needle inside haystack
        self.assertEqual([0x1000 + 13], ql.mem.search(b"\x0f\x01\x1e\x0d\x53\x11\x07\x1d\x53\x1d\x18", begin=0x1000 + 10, end=0x1000 + 30))

        # Needle before haystack
        self.assertEqual([], ql.mem.search(b"\x04\x0d\x1c\x53\x11\x07\x1d\x53\x0c\x07\x1f\x06", begin=0x1337))

        # Needle after haystack
        self.assertEqual([], ql.mem.search(b"\x1b\x09\x11\x53\x0f\x07\x07\x0c\x0a\x11\x0d", end=0x3000 + 13))

        # Needle exactly inside haystack
        self.assertEqual([0x2000 + 13], ql.mem.search(b"\x1a\x1d\x06\x53\x09\x1a\x07\x1d\x06\x0c", begin=0x2000 + 13, end=0x2000 + 23))

        # Needle 'tears' two mapped regions
        self.assertEqual([], ql.mem.search(b"\x1f\x00\x07\x53\x03\x06\x07\x1f\x1b", begin=0x1F00, end=0x200F))

        # Needle is a regex
        self.assertEqual([0x1000 + 11, 0x2000 + 11, 0x3000 + 43], ql.mem.search(re.compile(b"\x09\x53(\x0f|\x1a|\x04)[^\x0d]")))

        del ql

    def test_elf_linux_x8664_path_traversion(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/path_traverse_static"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)

        ql.os.stdout = pipe.SimpleOutStream(1)
        ql.run()

        self.assertNotIn("root\n", ql.os.stdout.read().decode("utf-8"))

        del ql


if __name__ == "__main__":
    unittest.main()
