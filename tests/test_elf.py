#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys, unittest, subprocess, string, random, os
sys.path.append("..")
from qiling import *
from qiling.const import *
from qiling.exception import *
from qiling.os.posix import syscall

class ELFTest(unittest.TestCase):

    def test_multithread_elf_linux_x86(self):
        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_multithreading"], "../examples/rootfs/x86_linux")
        ql.multithread = True   
        ql.run()
        del ql


    def test_multithread_elf_linux_x8664(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_multithreading"], "../examples/rootfs/x8664_linux", log_dir= "multi_log")
        ql.log_split = True
        ql.multithread = True   
        ql.run()
        del ql


    def test_multithread_elf_linux_mips32el(self):
        ql = Qiling(["../examples/rootfs/mips32el_linux/bin/mips32el_multithreading"], "../examples/rootfs/mips32el_linux")
        ql.multithread = True   
        ql.run()
        del ql


    def test_multithread_elf_linux_arm(self):
        ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_multithreading"], "../examples/rootfs/arm_linux")
        ql.multithread = True   
        ql.run()
        del ql


    def test_multithread_elf_linux_arm64(self):
        ql = Qiling(["../examples/rootfs/arm64_linux/bin/arm64_multithreading"], "../examples/rootfs/arm64_linux")
        ql.multithread = True   
        ql.run()
        del ql


    def test_elf_freebsd_x8664(self):     
        ql = Qiling(["../examples/rootfs/x8664_freebsd/bin/x8664_hello_asm"], "../examples/rootfs/x8664_freebsd", output = "dump")
        ql.run()
        del ql


    def test_elf_linux_x8664(self):
        def my_puts(ql, fn, ori_val):
            rdi = ql.register('RDI')
            print("puts(%s)" % ql.mem.string(rdi))
            ql.reg.pc = ori_val
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_args","1234test", "12345678", "bin/x8664_hello"],  "../examples/rootfs/x8664_linux", output="debug")
        ql.set_api('puts', my_puts)
        ql.run()
        del ql


    def test_tcp_elf_linux_x8664(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_tcp_test","20001"], "../examples/rootfs/x8664_linux")
        ql.multithread = True
        ql.run()
        del ql


    def test_tcp_elf_linux_arm(self):
        ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_tcp_test","20002"], "../examples/rootfs/arm_linux")
        ql.multithread = True
        ql.run()
        del ql


    def test_tcp_elf_linux_mips32el(self):
        ql = Qiling(["../examples/rootfs/mips32el_linux/bin/mips32el_tcp_test","20003"], "../examples/rootfs/mips32el_linux")
        ql.multithread = True
        ql.run()
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
            pathname = ql.os.file_des[read_fd].name.split('/')[-1]
        
            if pathname == "test_syscall_read.txt":
                print("test => read(%d, %s, %d)" % (read_fd, pathname, read_count))
                target = True

            syscall.ql_syscall_read(ql, read_fd, read_buf, read_count, *args)

            if target:
                real_path = ql.os.file_des[read_fd].name
                with open(real_path) as fd:
                    assert fd.read() == ql.mem.read(read_buf, read_count).decode()
                os.remove(real_path)

        def test_syscall_write(ql, write_fd, write_buf, write_count, *args):
            target = False
            pathname = ql.os.file_des[write_fd].name.split('/')[-1]

            if pathname == "test_syscall_write.txt":
                print("test => write(%d, %s, %d)" % (write_fd, pathname, write_count))
                target = True

            syscall.ql_syscall_write(ql, write_fd, write_buf, write_count, *args)

            if target:
                real_path = ql.os.file_des[write_fd].name
                with open(real_path) as fd:
                    assert fd.read() == 'Hello testing\x00'
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
                os.remove(real_path)

        def test_syscall_ftruncate(ql, ftrunc_fd, ftrunc_length, *args):
            target = False
            pathname = ql.os.file_des[ftrunc_fd].name.split('/')[-1]

            if pathname == "test_syscall_ftruncate.txt":
                print("test => ftruncate(%d, 0x%x)" % (ftrunc_fd, ftrunc_length))
                target = True

            syscall.ql_syscall_ftruncate(ql, ftrunc_fd, ftrunc_length, *args)

            if target:
                real_path = ql.os.transform_to_real_path(pathname)
                assert os.stat(real_path).st_size == 0x10
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
        ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_hello"], "../examples/rootfs/arm_linux", output = "debug", log_dir='logs')
        ql.log_split=True
        ql.run()
        del ql


    def test_elf_linux_arm_static(self):     
        ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_hello_static"], "../examples/rootfs/arm_linux", output = "default")
        ql.run()
        del ql


    # syscall testing for ARM, will be uncomment after ARM executable generated properly.
    # def test_elf_linux_arm_posix_syscall(self):
        # def test_syscall_read(ql, read_fd, read_buf, read_count, *args):
            # target = False
            # pathname = ql.os.file_des[read_fd].name.split('/')[-1]
        
            # if pathname == "test_syscall_read.txt":
                # print("test => read(%d, %s, %d)" % (read_fd, pathname, read_count))
                # target = True

            # syscall.ql_syscall_read(ql, read_fd, read_buf, read_count, *args)

            # if target:
                # real_path = ql.os.file_des[read_fd].name
                # with open(real_path) as fd:
                    # assert fd.read() == ql.mem.read(read_buf, read_count).decode()
                # os.remove(real_path)
 
        # def test_syscall_write(ql, write_fd, write_buf, write_count, *args):
            # target = False
            # pathname = ql.os.file_des[write_fd].name.split('/')[-1]

            # if pathname == "test_syscall_write.txt":
                # print("test => write(%d, %s, %d)" % (write_fd, pathname, write_count))
                # target = True

            # syscall.ql_syscall_write(ql, write_fd, write_buf, write_count, *args)

            # if target:
                # real_path = ql.os.file_des[write_fd].name
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
            # pathname = ql.os.file_des[ftrunc_fd].name.split('/')[-1]

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


    def test_elf_linux_arm64_posix_syscall(self):
        def test_syscall_read(ql, read_fd, read_buf, read_count, *args):
            target = False
            pathname = ql.os.file_des[read_fd].name.split('/')[-1]
        
            if pathname == "test_syscall_read.txt":
                print("test => read(%d, %s, %d)" % (read_fd, pathname, read_count))
                target = True

            syscall.ql_syscall_read(ql, read_fd, read_buf, read_count, *args)

            if target:
                real_path = ql.os.file_des[read_fd].name
                with open(real_path) as fd:
                    assert fd.read() == ql.mem.read(read_buf, read_count).decode()
                os.remove(real_path)
 
        def test_syscall_write(ql, write_fd, write_buf, write_count, *args):
            target = False
            pathname = ql.os.file_des[write_fd].name.split('/')[-1]

            if pathname == "test_syscall_write.txt":
                print("test => write(%d, %s, %d)" % (write_fd, pathname, write_count))
                target = True

            syscall.ql_syscall_write(ql, write_fd, write_buf, write_count, *args)

            if target:
                real_path = ql.os.file_des[write_fd].name
                with open(real_path) as fd:
                    assert fd.read() == 'Hello testing\x00'
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
                os.remove(real_path)

        def test_syscall_ftruncate(ql, ftrunc_fd, ftrunc_length, *args):
            target = False
            pathname = ql.os.file_des[ftrunc_fd].name.split('/')[-1]

            if pathname == "test_syscall_ftruncate.txt":
                print("test => ftruncate(%d, 0x%x)" % (ftrunc_fd, ftrunc_length))
                target = True

            syscall.ql_syscall_ftruncate(ql, ftrunc_fd, ftrunc_length, *args)

            if target:
                real_path = ql.os.transform_to_real_path(pathname)
                assert os.stat(real_path).st_size == 0x10
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
            pathname = ql.os.file_des[read_fd].name.split('/')[-1]
        
            if pathname == "test_syscall_read.txt":
                print("test => read(%d, %s, %d)" % (read_fd, pathname, read_count))
                target = True

            syscall.ql_syscall_read(ql, read_fd, read_buf, read_count, *args)

            if target:
                real_path = ql.os.file_des[read_fd].name
                with open(real_path) as fd:
                    assert fd.read() == ql.mem.read(read_buf, read_count).decode()
                os.remove(real_path)
 
        def test_syscall_write(ql, write_fd, write_buf, write_count, *args):
            target = False
            pathname = ql.os.file_des[write_fd].name.split('/')[-1]

            if pathname == "test_syscall_write.txt":
                print("test => write(%d, %s, %d)" % (write_fd, pathname, write_count))
                target = True

            syscall.ql_syscall_write(ql, write_fd, write_buf, write_count, *args)

            if target:
                real_path = ql.os.file_des[write_fd].name
                with open(real_path) as fd:
                    assert fd.read() == 'Hello testing\x00'
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
                os.remove(real_path)

        def test_syscall_ftruncate(ql, ftrunc_fd, ftrunc_length, *args):
            target = False
            pathname = ql.os.file_des[ftrunc_fd].name.split('/')[-1]

            if pathname == "test_syscall_ftruncate.txt":
                print("test => ftruncate(%d, 0x%x)" % (ftrunc_fd, ftrunc_length))
                target = True

            syscall.ql_syscall_ftruncate(ql, ftrunc_fd, ftrunc_length, *args)

            if target:
                real_path = ql.os.transform_to_real_path(pathname)
                assert os.stat(real_path).st_size == 0x10
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
            ql.nprint("0x%x" %  mapaddr)  
            try:
                buf = ql.mem.read(write_buf, write_count)
                ql.nprint("\n+++++++++\nmy write(%d,%x,%i) = %d\n+++++++++" % (write_fd, write_buf, write_count, regreturn))
                ql.os.file_des[write_fd].write(buf)
                regreturn = write_count
            except:
                regreturn = -1
                ql.nprint("\n+++++++++\nmy write(%d,%x,%i) = %d\n+++++++++" % (write_fd, write_buf, write_count, regreturn))
                if ql.output in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP):
                    raise
            ql.os.definesyscall_return(regreturn)

        ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_hello"], "../examples/rootfs/arm_linux")
        ql.set_syscall(0x04, my_syscall_write)
        ql.run()
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
                return os.fstat(sys.stdin.fileno())
 
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


        def run_one_round(payload):
            stdin = MyPipe()
            ql = Qiling(["../examples/rootfs/x86_linux/bin/crackme_linux"], "../examples/rootfs/x86_linux", output = "off", stdin = stdin)
            ins_count = [0]
            ql.hook_code(instruction_count, ins_count)
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


    def test_elf_linux_execve_x8664(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/posix_syscall_execve"],  "../examples/rootfs/x8664_linux", output="debug")
        ql.run()
        del ql



if __name__ == "__main__":
    unittest.main()
