#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys,unittest, subprocess, string, random
sys.path.append("..")
from qiling import *
from qiling.exception import *

class ELFTest(unittest.TestCase):


    # Not Stable, not suitable to use it as test
    # def test_multithread_elf_linux_x86(self):
    #    ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_multithreading"], "../examples/rootfs/x86_linux", output="debug")
    #    ql.run()

    def test_elf_freebsd_x8664(self):     
        ql = Qiling(["../examples/rootfs/x8664_freebsd/bin/x8664_hello_asm"], "../examples/rootfs/x8664_freebsd", output = "disasm")
        ql.run()  


    def test_elf_linux_x8664(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/tester","1234test", "12345678", "bin/x8664_hello"],  "../examples/rootfs/x8664_linux", output="debug")
        ql.run()


    def test_elf_linux_x8664_static(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_hello_static"], "../examples/rootfs/x86_linux", output="debug")
        ql.run()


    def test_elf_linux_x86(self):
        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_hello"], "../examples/rootfs/x86_linux", output="debug")
        ql.run()


    def test_elf_linux_x86_static(self):
        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_hello_static"], "../examples/rootfs/x86_linux", output="debug")
        ql.run()


    def test_elf_linux_arm(self):     
        ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_hello"], "../examples/rootfs/arm_linux", output = "default")
        ql.run()


    def test_elf_linux_arm_static(self):     
        ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_hello_static"], "../examples/rootfs/arm_linux", output = "default")
        ql.run()    


    def test_elf_linux_arm64(self):
        ql = Qiling(["../examples/rootfs/arm64_linux/bin/arm64_hello"], "../examples/rootfs/arm64_linux", output = "debug")
        ql.run()


    def test_elf_linux_arm64_static(self):    
        ql = Qiling(["../examples/rootfs/arm64_linux/bin/arm64_hello_static"], "../examples/rootfs/arm64_linux", output = "default")
        ql.run()


    def test_elf_linux_mips32el(self):
        def random_generator(size=6, chars=string.ascii_uppercase + string.digits):
            return ''.join(random.choice(chars) for x in range(size))

        ql = Qiling(["../examples/rootfs/mips32el_linux/bin/mips32el_hello", random_generator(random.randint(1,99))], "../examples/rootfs/mips32el_linux")
        ql.run()  


    # def test_elf_linux_mips32el_static(self): 
    #     create = [sys.executable, 'test_mips32el_linux_debug.py']
    #     try:
    #         subprocess.check_output(create,stderr=subprocess.STDOUT)
    #     except subprocess.CalledProcessError as e:    
    #         raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))    

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
            ql = Qiling(["../examples/rootfs/x86_linux/bin/crackme_linux"], "../examples/rootfs/x86_linux", output = "off", stdin = stdin, stdout = sys.stdout, stderr = sys.stderr)
            ins_count = [0]
            ql.hook_code(instruction_count, ins_count)
            stdin.write(payload)
            ql.run()
            del stdin
            del ql
            return ins_count[0]


        def solve():
            idx_list = [1, 4, 2, 0, 3]

            flag = b'\x00\x00\x00\x00\x00\n'

            old_count = run_one_round(flag)
            for idx in idx_list:
                for i in b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ':
                    flag = flag[ : idx] + chr(i).encode() + flag[idx + 1 : ]
                    tmp = run_one_round(flag)
                    if tmp > old_count:
                        old_count = tmp
                        break
                # if idx == 2:
                #     break

            print(flag)

        solve()


if __name__ == "__main__":
    unittest.main()