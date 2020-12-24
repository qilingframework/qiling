#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys, unittest, subprocess, string, random, os, logging

from unicorn import UcError, UC_ERR_READ_UNMAPPED, UC_ERR_FETCH_UNMAPPED

sys.path.append("..")
from qiling import *
from qiling.const import *
from qiling.exception import *
from qiling.os.posix import syscall
from qiling.os.mapper import QlFsMappedObject
from qiling.os.stat import Fstat

class ELFTest(unittest.TestCase):


    def test_libpatch_elf_linux_x8664(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/patch_test.bin"], "../examples/rootfs/x8664_linux")
        ql.patch(0x0000000000000575, b'qiling\x00', file_name = b'libpatch_test.so')  
        ql.run()
        del ql


    def test_elf_freebsd_x8664(self):     
        ql = Qiling(["../examples/rootfs/x8664_freebsd/bin/x8664_hello_asm"], "../examples/rootfs/x8664_freebsd", output = "dump")
        ql.run()
        del ql


    def test_elf_partial_linux_x8664(self):
        ss = None

        def dump(ql, *args, **kw):
            ql.save(reg=False, cpu_context=True, snapshot="/tmp/snapshot.bin")
            ql.emu_stop()

        ql = Qiling(["../examples/rootfs/x8664_linux/bin/sleep_hello"], "../examples/rootfs/x8664_linux", output= "default")
        X64BASE = int(ql.profile.get("OS64", "load_address"), 16)
        ql.hook_address(dump, X64BASE + 0x1094)
        ql.run()

        ql = Qiling(["../examples/rootfs/x8664_linux/bin/sleep_hello"], "../examples/rootfs/x8664_linux", output= "debug", verbose=4)
        X64BASE = int(ql.profile.get("OS64", "load_address"), 16)
        ql.restore(snapshot="/tmp/snapshot.bin")
        begin_point = X64BASE + 0x109e
        end_point = X64BASE + 0x10bc
        ql.run(begin = begin_point, end = end_point)

        del ql


    def test_elf_linux_x8664(self):
        def my_puts(ql):
            addr = ql.os.function_arg[0]
            print("puts(%s)" % ql.mem.string(addr))
            reg = ql.reg.read("rax")
            print("reg : 0x%x" % reg)
            ql.reg.rax = reg
            self.set_api = reg

        def write_onEnter(ql, arg1, arg2, arg3, *args):
            print("enter write syscall!")
            ql.reg.rsi = arg2 + 1
            ql.reg.rdx = arg3 - 1
            self.set_api_onenter = True

        def write_onexit(ql, arg1, arg2, arg3, *args):
            print("exit write syscall!")
            ql.reg.rax = arg3 + 1
            self.set_api_onexit = True

        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_args","1234test", "12345678", "bin/x8664_hello"],  "../examples/rootfs/x8664_linux", output="debug")
        ql.set_syscall(1, write_onEnter, QL_INTERCEPT.ENTER)
        ql.set_api('puts', my_puts)
        ql.set_syscall(1, write_onexit, QL_INTERCEPT.EXIT)
        ql.mem.map(0x1000, 0x1000)
        ql.mem.write(0x1000, b"\xFF\xFE\xFD\xFC\xFB\xFA\xFB\xFC\xFC\xFE\xFD")
        ql.mem.map(0x2000, 0x1000)
        ql.mem.write(0x2000, b"\xFF\xFE\xFD\xFC\xFB\xFA\xFB\xFC\xFC\xFE\xFD")
        ql.run()

        self.assertEqual([0x1000,0x2000], ql.mem.search(b"\xFF\xFE\xFD\xFC\xFB\xFA\xFB\xFC\xFC\xFE\xFD"))
        self.assertEqual(93824992233162, self.set_api)
        self.assertEqual(True, self.set_api_onexit)
        self.assertEqual(True, self.set_api_onenter)

        del self.set_api
        del self.set_api_onexit
        del self.set_api_onenter
        del ql


    def test_elf_hijackapi_linux_x8664(self):
        def my_puts_enter(ql):
            addr = ql.os.function_arg[0]
            self.test_enter_str = ql.mem.string(addr)

        def my_puts_exit(ql):
            self.test_exit_rdi = ql.reg.rdi

        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_puts"],  "../examples/rootfs/x8664_linux", output="debug")
        ql.set_api('puts', my_puts_enter, QL_INTERCEPT.ENTER)
        ql.set_api('puts', my_puts_exit, QL_INTERCEPT.EXIT)

        ql.run()

        self.assertEqual(0x1, self.test_exit_rdi)
        self.assertEqual("CCCC", self.test_enter_str)
        
        del self.test_exit_rdi
        del self.test_enter_str
        del ql         


    def test_elf_linux_x8664_static(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_hello_static"], "../examples/rootfs/x8664_linux", output="debug")
        ql.run()
        del ql


    def test_elf_linux_x86(self):
        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_hello"], "../examples/rootfs/x86_linux", output="debug")     
        ql.run()
        del ql


    def test_elf_linux_x86_static(self):
        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_hello_static"], "../examples/rootfs/x86_linux", output="debug")
        ql.run()
        del ql


    def test_elf_linux_x86_posix_syscall(self):
        def test_syscall_read(ql, read_fd, read_buf, read_count, *args):
            target = False
            pathname = ql.os.fd[read_fd].name.split('/')[-1]
        
            if pathname == "test_syscall_read.txt":
                print("test => read(%d, %s, %d)" % (read_fd, pathname, read_count))
                target = True

            syscall.ql_syscall_read(ql, read_fd, read_buf, read_count, *args)

            if target:
                real_path = ql.os.fd[read_fd].name
                with open(real_path) as fd:
                    assert fd.read() == ql.mem.read(read_buf, read_count).decode()
                if ql.platform == QL_OS.WINDOWS:
                    return
                else:    
                    os.remove(real_path)

        def test_syscall_write(ql, write_fd, write_buf, write_count, *args):
            target = False
            pathname = ql.os.fd[write_fd].name.split('/')[-1]

            if pathname == "test_syscall_write.txt":
                print("test => write(%d, %s, %d)" % (write_fd, pathname, write_count))
                target = True

            syscall.ql_syscall_write(ql, write_fd, write_buf, write_count, *args)

            if target:
                real_path = ql.os.fd[write_fd].name
                with open(real_path) as fd:
                    assert fd.read() == 'Hello testing\x00'
                if ql.platform == QL_OS.WINDOWS:
                    return
                else:    
                    os.remove(real_path)

        def test_syscall_openat(ql, openat_fd, openat_path, openat_flags, openat_mode, *args):
            target = False
            pathname = ql.mem.string(openat_path)

            if pathname == "test_syscall_open.txt":
                print("test => openat(%d, %s, 0x%x, 0%o)" % (openat_fd, pathname, openat_flags, openat_mode))
                target = True

            syscall.ql_syscall_openat(ql, openat_fd, openat_path, openat_flags, openat_mode, *args)

            if target:
                real_path = ql.os.transform_to_real_path(pathname)
                assert os.path.isfile(real_path) == True
                if ql.platform == QL_OS.WINDOWS:
                    return
                else:    
                    os.remove(real_path)

        def test_syscall_unlink(ql, unlink_pathname, *args):
            target = False
            pathname = ql.mem.string(unlink_pathname)

            if pathname == "test_syscall_unlink.txt":
                print("test => unlink(%s)" % (pathname))
                target = True

            syscall.ql_syscall_unlink(ql, unlink_pathname, *args)

            if target:
                real_path = ql.os.transform_to_real_path(pathname)
                assert os.path.isfile(real_path) == False

        def test_syscall_truncate(ql, trunc_pathname, trunc_length, *args):
            target = False
            pathname = ql.mem.string(trunc_pathname)

            if pathname == "test_syscall_truncate.txt":
                print("test => truncate(%s, 0x%x)" % (pathname, trunc_length))
                target = True

            syscall.ql_syscall_truncate(ql, trunc_pathname, trunc_length, *args)

            if target:
                real_path = ql.os.transform_to_real_path(pathname)
                assert os.stat(real_path).st_size == 0
                if ql.platform == QL_OS.WINDOWS:
                    return
                else:    
                    os.remove(real_path)

        def test_syscall_ftruncate(ql, ftrunc_fd, ftrunc_length, *args):
            target = False
            pathname = ql.os.fd[ftrunc_fd].name.split('/')[-1]
            
            reg = ql.reg.read("eax")
            print("reg : 0x%x" % reg)
            ql.reg.eax = reg 

            if pathname == "test_syscall_ftruncate.txt":
                print("test => ftruncate(%d, 0x%x)" % (ftrunc_fd, ftrunc_length))
                target = True

            syscall.ql_syscall_ftruncate(ql, ftrunc_fd, ftrunc_length, *args)

            if target:
                real_path = ql.os.transform_to_real_path(pathname)
                assert os.stat(real_path).st_size == 0x10
                if ql.platform == QL_OS.WINDOWS:
                    return
                else:    
                    os.remove(real_path)

        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_posix_syscall"], "../examples/rootfs/x86_linux", output="debug")
        ql.set_syscall(0x3, test_syscall_read)
        ql.set_syscall(0x4, test_syscall_write)
        ql.set_syscall(0x127, test_syscall_openat)
        ql.set_syscall(0xa, test_syscall_unlink)
        ql.set_syscall(0x5c, test_syscall_truncate)
        ql.set_syscall(0x5d, test_syscall_ftruncate)
        ql.run()
        del ql


    def test_elf_linux_arm(self):     
        def my_puts(ql):
            addr = ql.os.function_arg[0]
            print("puts(%s)" % ql.mem.string(addr))
            all_mem = ql.mem.save()
            ql.mem.restore(all_mem)
            
        ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_hello"], "../examples/rootfs/arm_linux", output = "debug", profile='profiles/append_test.ql', log_split=True)
        ql.set_api('puts', my_puts)
        ql.run()
        del ql


    def test_elf_linux_arm_static(self):     
        ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_hello_static"], "../examples/rootfs/arm_linux", output = "default")
        all_mem = ql.mem.save()
        ql.mem.restore(all_mem)
        ql.run()
        del ql


    # syscall testing for ARM, will be uncomment after ARM executable generated properly.
    # def test_elf_linux_arm_posix_syscall(self):
        # def test_syscall_read(ql, read_fd, read_buf, read_count, *args):
            # target = False
            # pathname = ql.os.fd[read_fd].name.split('/')[-1]
        
            # if pathname == "test_syscall_read.txt":
                # print("test => read(%d, %s, %d)" % (read_fd, pathname, read_count))
                # target = True

            # syscall.ql_syscall_read(ql, read_fd, read_buf, read_count, *args)

            # if target:
                # real_path = ql.os.fd[read_fd].name
                # with open(real_path) as fd:
                    # assert fd.read() == ql.mem.read(read_buf, read_count).decode()
                # os.remove(real_path)
 
        # def test_syscall_write(ql, write_fd, write_buf, write_count, *args):
            # target = False
            # pathname = ql.os.fd[write_fd].name.split('/')[-1]

            # if pathname == "test_syscall_write.txt":
                # print("test => write(%d, %s, %d)" % (write_fd, pathname, write_count))
                # target = True

            # syscall.ql_syscall_write(ql, write_fd, write_buf, write_count, *args)

            # if target:
                # real_path = ql.os.fd[write_fd].name
                # with open(real_path) as fd:
                    # assert fd.read() == 'Hello testing\x00'
                # os.remove(real_path)

        # def test_syscall_open(ql, open_pathname, open_flags, open_mode, *args):
            # target = False
            # pathname = ql.mem.string(open_pathname)

            # if pathname == "test_syscall_open.txt":
                # print("test => open(%s, 0x%x, 0%o)" % (pathname, open_flags, open_mode))
                # target = True

            # syscall.ql_syscall_open(ql, open_pathname, open_flags, open_mode, *args)

            # if target:
                # real_path = ql.os.transform_to_real_path(pathname)
                # assert os.path.isfile(real_path) == True
                # os.remove(real_path)

        # def test_syscall_unlink(ql, unlink_pathname, *args):
            # target = False
            # pathname = ql.mem.string(unlink_pathname)

            # if pathname == "test_syscall_unlink.txt":
                # print("test => unlink(%s)" % (pathname))
                # target = True

            # syscall.ql_syscall_unlink(ql, unlink_pathname, *args)

            # if target:
                # real_path = ql.os.transform_to_real_path(pathname)
                # assert os.path.isfile(real_path) == False

        # def test_syscall_truncate(ql, trunc_pathname, trunc_length, *args):
            # target = False
            # pathname = ql.mem.string(trunc_pathname)

            # if pathname == "test_syscall_truncate.txt":
                # print("test => truncate(%s, 0x%x)" % (pathname, trunc_length))
                # target = True

            # syscall.ql_syscall_truncate(ql, trunc_pathname, trunc_length, *args)

            # if target:
                # real_path = ql.os.transform_to_real_path(pathname)
                # assert os.stat(real_path).st_size == 0
                # os.remove(real_path)

        # def test_syscall_ftruncate(ql, ftrunc_fd, ftrunc_length, *args):
            # target = False
            # pathname = ql.os.fd[ftrunc_fd].name.split('/')[-1]

            # if pathname == "test_syscall_ftruncate.txt":
                # print("test => ftruncate(%d, 0x%x)" % (ftrunc_fd, ftrunc_length))
                # target = True

            # syscall.ql_syscall_ftruncate(ql, ftrunc_fd, ftrunc_length, *args)

            # if target:
                # real_path = ql.os.transform_to_real_path(pathname)
                # assert os.stat(real_path).st_size == 0x10
                # os.remove(real_path)

        # ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_posix_syscall"], "../examples/rootfs/arm_linux", output="debug")
        # ql.set_syscall(0x3, test_syscall_read)
        # ql.set_syscall(0x4, test_syscall_write)
        # ql.set_syscall(0x5, test_syscall_open)
        # ql.set_syscall(0xa, test_syscall_unlink)
        # ql.set_syscall(0x5c, test_syscall_truncate)
        # ql.set_syscall(0x5d, test_syscall_ftruncate)
        # ql.run()
        # del ql


    def test_elf_linux_arm64(self):
        ql = Qiling(["../examples/rootfs/arm64_linux/bin/arm64_hello"], "../examples/rootfs/arm64_linux", output = "debug")
        ql.run()
        del ql


    def test_elf_linux_arm64_static(self):    
        ql = Qiling(["../examples/rootfs/arm64_linux/bin/arm64_hello_static"], "../examples/rootfs/arm64_linux", output = "default")
        ql.run()
        del ql


    def test_elf_linux_mips32_static(self):
       ql = Qiling(["../examples/rootfs/mips32_linux/bin/mips32_hello_static"], "../examples/rootfs/mips32_linux")
       ql.run()
       del ql


    def test_elf_linux_mips32(self):
        def random_generator(size=6, chars=string.ascii_uppercase + string.digits):
            return ''.join(random.choice(chars) for x in range(size))

        ql = Qiling(["../examples/rootfs/mips32_linux/bin/mips32_hello", random_generator(random.randint(1,99))], "../examples/rootfs/mips32_linux")
        ql.run()

        del ql


    def test_elf_onEnter_mips32el(self):
        def my_puts_onenter(ql):
            addr = ql.os.function_arg[0]
            print("puts(%s)" % ql.mem.string(addr))
            self.my_puts_onenter_addr = addr
            return 2

        ql = Qiling(["../examples/rootfs/mips32el_linux/bin/mips32el_double_hello"], "../examples/rootfs/mips32el_linux")
        ql.set_api('puts', my_puts_onenter, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertEqual(4196680, self.my_puts_onenter_addr)

        del ql


    def test_elf_linux_arm64_posix_syscall(self):
        def test_syscall_read(ql, read_fd, read_buf, read_count, *args):
            target = False
            pathname = ql.os.fd[read_fd].name.split('/')[-1]
            
            reg = ql.reg.read("x0")
            print("reg : 0x%x" % reg)
            ql.reg.x0 = reg  
        
            if pathname == "test_syscall_read.txt":
                print("test => read(%d, %s, %d)" % (read_fd, pathname, read_count))
                target = True

            syscall.ql_syscall_read(ql, read_fd, read_buf, read_count, *args)

            if target:
                real_path = ql.os.fd[read_fd].name
                with open(real_path) as fd:
                    assert fd.read() == ql.mem.read(read_buf, read_count).decode()
                if ql.platform == QL_OS.WINDOWS:
                    return
                else:    
                    os.remove(real_path)


        def test_syscall_write(ql, write_fd, write_buf, write_count, *args):
            target = False
            pathname = ql.os.fd[write_fd].name.split('/')[-1]

            if pathname == "test_syscall_write.txt":
                print("test => write(%d, %s, %d)" % (write_fd, pathname, write_count))
                target = True

            syscall.ql_syscall_write(ql, write_fd, write_buf, write_count, *args)

            if target:
                real_path = ql.os.fd[write_fd].name
                with open(real_path) as fd:
                    assert fd.read() == 'Hello testing\x00'
                if ql.platform == QL_OS.WINDOWS:
                    return
                else:    
                    os.remove(real_path)


        def test_syscall_openat(ql, openat_fd, openat_path, openat_flags, openat_mode, *args):
            target = False
            pathname = ql.mem.string(openat_path)

            if pathname == "test_syscall_open.txt":
                print("test => openat(%d, %s, 0x%x, 0%o)" % (openat_fd, pathname, openat_flags, openat_mode))
                target = True

            syscall.ql_syscall_openat(ql, openat_fd, openat_path, openat_flags, openat_mode, *args)

            if target:
                real_path = ql.os.transform_to_real_path(pathname)
                assert os.path.isfile(real_path) == True
                if ql.platform == QL_OS.WINDOWS:
                    return
                else:    
                    os.remove(real_path)


        def test_syscall_unlink(ql, unlink_pathname, *args):
            target = False
            pathname = ql.mem.string(unlink_pathname)

            if pathname == "test_syscall_unlink.txt":
                print("test => unlink(%s)" % (pathname))
                target = True

            syscall.ql_syscall_unlink(ql, unlink_pathname, *args)

            if target:
                real_path = ql.os.transform_to_real_path(pathname)
                assert os.path.isfile(real_path) == False


        def test_syscall_truncate(ql, trunc_pathname, trunc_length, *args):
            target = False
            pathname = ql.mem.string(trunc_pathname)

            if pathname == "test_syscall_truncate.txt":
                print("test => truncate(%s, 0x%x)" % (pathname, trunc_length))
                target = True

            syscall.ql_syscall_truncate(ql, trunc_pathname, trunc_length, *args)

            if target:
                real_path = ql.os.transform_to_real_path(pathname)
                assert os.stat(real_path).st_size == 0
                if ql.platform == QL_OS.WINDOWS:
                    return
                else:    
                    os.remove(real_path)


        def test_syscall_ftruncate(ql, ftrunc_fd, ftrunc_length, *args):
            target = False
            pathname = ql.os.fd[ftrunc_fd].name.split('/')[-1]

            if pathname == "test_syscall_ftruncate.txt":
                print("test => ftruncate(%d, 0x%x)" % (ftrunc_fd, ftrunc_length))
                target = True

            syscall.ql_syscall_ftruncate(ql, ftrunc_fd, ftrunc_length, *args)

            if target:
                real_path = ql.os.transform_to_real_path(pathname)
                assert os.stat(real_path).st_size == 0x10
                if ql.platform == QL_OS.WINDOWS:
                    return
                else:    
                    os.remove(real_path)

        ql = Qiling(["../examples/rootfs/arm64_linux/bin/arm64_posix_syscall"], "../examples/rootfs/arm64_linux", output="debug")
        ql.set_syscall(0x3f, test_syscall_read)
        ql.set_syscall(0x40, test_syscall_write)
        ql.set_syscall(0x38, test_syscall_openat)
        ql.set_syscall(0x402, test_syscall_unlink)
        ql.set_syscall(0x2d, test_syscall_truncate)
        ql.set_syscall(0x2e, test_syscall_ftruncate)
        ql.run()
        del ql


    def test_elf_linux_mips32el(self):
        def random_generator(size=6, chars=string.ascii_uppercase + string.digits):
            return ''.join(random.choice(chars) for x in range(size))

        ql = Qiling(["../examples/rootfs/mips32el_linux/bin/mips32el_hello", random_generator(random.randint(1,99))], "../examples/rootfs/mips32el_linux")
        ql.run()
        del ql


    def test_elf_linux_mips32el_static(self):
        def random_generator(size=6, chars=string.ascii_uppercase + string.digits):
            return ''.join(random.choice(chars) for x in range(size))

        ql = Qiling(["../examples/rootfs/mips32el_linux/bin/mips32el_hello_static", random_generator(random.randint(1,99))], "../examples/rootfs/mips32el_linux")
        ql.run()
        del ql 


    def test_elf_linux_mips32el_posix_syscall(self):
        def test_syscall_read(ql, read_fd, read_buf, read_count, *args):
            target = False
            pathname = ql.os.fd[read_fd].name.split('/')[-1]
            
            reg = ql.reg.read("v0")
            print("reg : 0x%x" % reg)
            ql.reg.v0 = reg  
            
            if pathname == "test_syscall_read.txt":
                print("test => read(%d, %s, %d)" % (read_fd, pathname, read_count))
                target = True

            syscall.ql_syscall_read(ql, read_fd, read_buf, read_count, *args)

            if target:
                real_path = ql.os.fd[read_fd].name
                with open(real_path) as fd:
                    assert fd.read() == ql.mem.read(read_buf, read_count).decode()
                if ql.platform == QL_OS.WINDOWS:
                    return
                else:    
                    os.remove(real_path)
 
        def test_syscall_write(ql, write_fd, write_buf, write_count, *args):
            target = False
            pathname = ql.os.fd[write_fd].name.split('/')[-1]

            if pathname == "test_syscall_write.txt":
                print("test => write(%d, %s, %d)" % (write_fd, pathname, write_count))
                target = True

            syscall.ql_syscall_write(ql, write_fd, write_buf, write_count, *args)

            if target:
                real_path = ql.os.fd[write_fd].name
                with open(real_path) as fd:
                    assert fd.read() == 'Hello testing\x00'
                if ql.platform == QL_OS.WINDOWS:
                    return
                else:    
                    os.remove(real_path)

        def test_syscall_open(ql, open_pathname, open_flags, open_mode, *args):
            target = False
            pathname = ql.mem.string(open_pathname)

            if pathname == "test_syscall_open.txt":
                print("test => open(%s, 0x%x, 0%o)" % (pathname, open_flags, open_mode))
                target = True

            syscall.ql_syscall_open(ql, open_pathname, open_flags, open_mode, *args)

            if target:
                real_path = ql.os.transform_to_real_path(pathname)
                assert os.path.isfile(real_path) == True
                if ql.platform == QL_OS.WINDOWS:
                    return
                else:    
                    os.remove(real_path)

        def test_syscall_unlink(ql, unlink_pathname, *args):
            target = False
            pathname = ql.mem.string(unlink_pathname)

            if pathname == "test_syscall_unlink.txt":
                print("test => unlink(%s)" % (pathname))
                target = True

            syscall.ql_syscall_unlink(ql, unlink_pathname, *args)

            if target:
                real_path = ql.os.transform_to_real_path(pathname)
                assert os.path.isfile(real_path) == False

        def test_syscall_truncate(ql, trunc_pathname, trunc_length, *args):
            target = False
            pathname = ql.mem.string(trunc_pathname)

            if pathname == "test_syscall_truncate.txt":
                print("test => truncate(%s, 0x%x)" % (pathname, trunc_length))
                target = True

            syscall.ql_syscall_truncate(ql, trunc_pathname, trunc_length, *args)

            if target:
                real_path = ql.os.transform_to_real_path(pathname)
                assert os.stat(real_path).st_size == 0
                if ql.platform == QL_OS.WINDOWS:
                    return
                else:    
                    os.remove(real_path)

        def test_syscall_ftruncate(ql, ftrunc_fd, ftrunc_length, *args):
            target = False
            pathname = ql.os.fd[ftrunc_fd].name.split('/')[-1]

            if pathname == "test_syscall_ftruncate.txt":
                print("test => ftruncate(%d, 0x%x)" % (ftrunc_fd, ftrunc_length))
                target = True

            syscall.ql_syscall_ftruncate(ql, ftrunc_fd, ftrunc_length, *args)

            if target:
                real_path = ql.os.transform_to_real_path(pathname)
                assert os.stat(real_path).st_size == 0x10
                if ql.platform == QL_OS.WINDOWS:
                    return
                else:    
                    os.remove(real_path)

        ql = Qiling(["../examples/rootfs/mips32el_linux/bin/mips32el_posix_syscall"], "../examples/rootfs/mips32el_linux", output="debug")
        ql.set_syscall(4003, test_syscall_read)
        ql.set_syscall(4004, test_syscall_write)
        ql.set_syscall(4005, test_syscall_open)
        ql.set_syscall(4010, test_syscall_unlink)
        ql.set_syscall(4092, test_syscall_truncate)
        ql.set_syscall(4093, test_syscall_ftruncate)
        ql.run()


    def test_elf_linux_arm_custom_syscall(self):
        def my_syscall_write(ql, write_fd, write_buf, write_count, *args, **kw):
            regreturn = 0
            buf = None
            mapaddr = ql.mem.map_anywhere(0x100000)
            logging.info("0x%x" %  mapaddr)
            
            reg = ql.reg.read("r0")
            print("reg : 0x%x" % reg)
            ql.reg.r0 = reg
            
            
            try:
                buf = ql.mem.read(write_buf, write_count)
                logging.info("\n+++++++++\nmy write(%d,%x,%i) = %d\n+++++++++" % (write_fd, write_buf, write_count, regreturn))
                ql.os.fd[write_fd].write(buf)
                regreturn = write_count
            except:
                regreturn = -1
                logging.info("\n+++++++++\nmy write(%d,%x,%i) = %d\n+++++++++" % (write_fd, write_buf, write_count, regreturn))
                if ql.output in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP):
                    raise
            ql.os.definesyscall_return(regreturn)
            self.set_syscall = reg

        ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_hello"], "../examples/rootfs/arm_linux")
        ql.set_syscall(0x04, my_syscall_write)
        ql.run()
        
        self.assertEqual(1, self.set_syscall)
        
        del self.set_syscall
        del ql


    def test_elf_linux_x86_crackme(self):
        class MyPipe():
            def __init__(self):
                self.buf = b''

            def write(self, s):
                self.buf += s

            def read(self, l):
                if l <= len(self.buf):
                    ret = self.buf[ : l]
                    self.buf = self.buf[l : ]
                else:
                    ret = self.buf
                    self.buf = ''
                return ret

            def fileno(self):
                return 0

            def fstat(self):
                return Fstat(sys.stdin.fileno())
 
            def show(self):
                pass

            def clear(self):
                pass

            def flush(self):
                pass

            def close(self):
                self.outpipe.close()


        def instruction_count(ql, address, size, user_data):
            user_data[0] += 1

        def my__llseek(ql, *args, **kw):
            pass

        def run_one_round(payload):
            stdin = MyPipe()
            ql = Qiling(["../examples/rootfs/x86_linux/bin/crackme_linux"], "../examples/rootfs/x86_linux", console = False, stdin = stdin)
            ins_count = [0]
            ql.hook_code(instruction_count, ins_count)
            ql.set_syscall("_llseek", my__llseek)
            stdin.write(payload)
            ql.run()
            del stdin
            return ins_count[0]


        def solve():
            idx_list = [1, 4, 2, 0, 3]

            flag = b'\x00\x00\x00\x00\x00\n'

            old_count = run_one_round(flag)
            for idx in idx_list:
                for i in b'L1NUX\\n':
                    flag = flag[ : idx] + chr(i).encode() + flag[idx + 1 : ]
                    tmp = run_one_round(flag)
                    if tmp > old_count:
                        old_count = tmp
                        break
                # if idx == 2:
                #     break

            print(flag)

        print("\n\n Linux Simple Crackme Brute Force, This Will Take Some Time ...")
        solve()

    def test_x86_fake_urandom_multiple_times(self):
        fake_id = 0
        ids = []
        class Fake_urandom(QlFsMappedObject):

            def __init__(self):
                nonlocal fake_id
                self.id = fake_id
                fake_id += 1
                ids.append(self.id)
                logging.info(f"Creating Fake_urandom with id {self.id}")

            def read(self, size):
                return b'\x01'
            
            def fstat(self):
                return -1
            
            def close(self):
                return 0

        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_fetch_urandom_multiple_times"],  "../examples/rootfs/x86_linux", output="debug")
        # Note we pass in a class here.
        ql.add_fs_mapper("/dev/urandom", Fake_urandom)

        ql.exit_code = 0
        ql.exit_group_code = 0

        def check_exit_group_code(ql, exit_code, *args, **kw):
            ql.exit_group_code = exit_code

        def check_exit_code(ql, exit_code, *args, **kw):
            ql.exit_code = exit_code            

        ql.set_syscall("exit_group", check_exit_group_code, QL_INTERCEPT.ENTER)
        ql.set_syscall("exit", check_exit_code, QL_INTERCEPT.ENTER)

        ql.run()
        self.assertEqual(0, ql.exit_code)
        self.assertEqual(0, ql.exit_group_code)
        last = -1
        for i in ids:
            self.assertEqual(last + 1, i)
            last = i
        del ql
        

    def test_x86_fake_urandom(self):
        class Fake_urandom(QlFsMappedObject):

            def read(self, size):
                return b"\x01"

            def fstat(self):
                return -1
            
            def close(self):
                return 0

        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_fetch_urandom"],  "../examples/rootfs/x86_linux", output="debug")
        ql.add_fs_mapper("/dev/urandom", Fake_urandom())

        ql.exit_code = 0
        ql.exit_group_code = 0

        def check_exit_group_code(ql, exit_code, *args, **kw):
            ql.exit_group_code = exit_code

        def check_exit_code(ql, exit_code, *args, **kw):
            ql.exit_code = exit_code            

        ql.set_syscall("exit_group", check_exit_group_code, QL_INTERCEPT.ENTER)
        ql.set_syscall("exit", check_exit_code, QL_INTERCEPT.ENTER)

        ql.run()
        self.assertEqual(0, ql.exit_code)
        self.assertEqual(0, ql.exit_group_code)        
        del ql


    def test_x8664_map_urandom(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_fetch_urandom"],  "../examples/rootfs/x8664_linux", output="debug")
        ql.add_fs_mapper("/dev/urandom","/dev/urandom")
        
        ql.exit_code = 0
        ql.exit_group_code = 0

        def check_exit_group_code(ql, exit_code, *args, **kw):
            ql.exit_group_code = exit_code

        def check_exit_code(ql, exit_code, *args, **kw):
            ql.exit_code = exit_code            

        ql.set_syscall("exit_group", check_exit_group_code, QL_INTERCEPT.ENTER)
        ql.set_syscall("exit", check_exit_code, QL_INTERCEPT.ENTER)

        ql.run()

        self.assertEqual(0, ql.exit_code)
        self.assertEqual(0, ql.exit_group_code)

        del ql


    def test_x8664_symlink(self):
        ql = Qiling(["../examples/rootfs/x8664_linux_symlink/bin/x8664_hello"],  "../examples/rootfs/x8664_linux_symlink", output="debug")
        ql.run()
        del ql

    def test_demigod_m0hamed_x86(self):
        ql = Qiling(["../examples/rootfs/x86_linux/kernel/m0hamed_rootkit.ko"],  "../examples/rootfs/x86_linux", output="disasm")
        try:
            procfile_read_func_begin = ql.loader.load_address + 0x11e0
            procfile_read_func_end = ql.loader.load_address + 0x11fa
            ql.run(begin=procfile_read_func_begin, end=procfile_read_func_end)
        except UcError as e:
            print(e)
            sys.exit(-1)
        del ql

    def test_demigod_m0hamed_x8664(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/kernel/m0hamed_rootkit.ko"],  "../examples/rootfs/x8664_linux", output="disasm")
        try:
            ql.run()
        except UcError as e:
            print(e)
            sys.exit(-1)
        del ql

    def test_demigod_hello_mips32(self):
        ql = Qiling(["../examples/rootfs/mips32_linux/kernel/hello.ko"],  "../examples/rootfs/mips32_linux", output="debug")
        begin = ql.loader.load_address + 0x1060
        end = ql.loader.load_address + 0x1084
        ql.run(begin=begin, end=end)
        del ql

    def test_x8664_absolute_path(self):
        class MyPipe():
            def __init__(self):
                self.buf = b''

            def write(self, s):
                self.buf += s

            def read(self, l):
                pass

            def fileno(self):
                return 0

            def fstat(self):
                return Fstat(sys.stdin.fileno())
 
            def show(self):
                pass

            def clear(self):
                pass

            def flush(self):
                pass

            def close(self):
                pass
        
        pipe = MyPipe()
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/absolutepath"],  "../examples/rootfs/x8664_linux", output="debug", stdout=pipe)

        ql.run()
        
        self.assertEqual(pipe.buf, b'test_complete\n\ntest_complete\n\n')

        del ql

    def test_x8664_getcwd(self):
        class MyPipe():
            def __init__(self):
                self.buf = b''

            def write(self, s):
                self.buf += s

            def read(self, l):
                pass

            def fileno(self):
                return 0

            def fstat(self):
                return Fstat(sys.stdin.fileno())
 
            def show(self):
                pass

            def clear(self):
                pass

            def flush(self):
                pass

            def close(self):
                pass
        
        pipe = MyPipe()
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/testcwd"],  "../examples/rootfs/x8664_linux", output="debug", stdout=pipe)

        ql.run()
        self.assertEqual(pipe.buf, b'/\n/lib\n/bin\n/\n')

        del ql

if __name__ == "__main__":
    unittest.main()
