#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os, sys, unittest
import binascii

sys.path.append("..")
from qiling import *


# This is mostly taken from the crackmes
class CustomPipe():
    def __init__(self):
        self.buf = b''

    def write(self, s):
        self.buf += s

    def read(self, size):
        raise NotImplementedError("You should implement this function in a subclass")

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

    def fstat(self):
        return stdin_fstat


class InteractPipe(CustomPipe):
    
    def __init__(self, input_data = b''):
        super(InteractPipe, self).__init__()
        self.buf = input_data

    def read(self, size):
        # when not in fuzzing, ask the user for moar bytes
        while len(self.buf) < size:
            new_input = input('read({0:d}) = {1:s}'.format(size - len(self.buf), self.buf.decode('ascii')))
            self.buf+=new_input.encode("ascii") # ql.mem expect bytes, not str
        ret = self.buf[: size]
        self.buf = self.buf[size:]
        return ret



class TestSparc(unittest.TestCase):

    def test_simple_ctf_challenge(self):

        def hook_and_ret(ql, address, hook_callback):
            """ completely emulate the function in python and instead jump on a ret """

            ret_instruction = binascii.unhexlify("".join([
                "81 C3 E0 08",  # retl
                "01 00 00 00",  # nop        // delay slot
            ]).replace(" ", ""))

            # patching the original instruction with a ret
            ql.mem.write(address, ret_instruction)

            # over-patching our patch with a bp :)
            ql.hook_address(hook_callback, address)

        def puts_hook(ql):
            ''' '''
            arg0 = ql.reg.o0
            msg = ql.mem.string(arg0)
            print('puts({})'.format(msg))

            # success condition
            if "FLAG{" in msg:
                exit_hook(ql)

        def printf_hook(ql):
            """ partial implementation of a printf function with variadic args """
            format_string_addr = ql.reg.o0
            format_string = ql.mem.string(format_string_addr)
            va_list_n = format_string.count(r"%")
            va_list = []

            i = 0
            index = 0
            while True:
                index = format_string.find(r"%", (0, index + 1)[index != 0])
                if index == -1:
                    break

                if i >= va_list_n:
                    break
                
                c = format_string[index+1]
                reg = getattr(ql.reg, "o%d" % (i + 1))

                if c == "d":
                    arg = reg 
                elif c == "x":
                    arg = reg 
                elif c == "s":
                    arg = ql.mem.string(reg)
                        
                va_list.append(arg)
                i+=1        
            
            msg = format_string % (*va_list,)
            print('printf({})'.format(repr(msg)))


        def read_hook(ql):
            """ Instead of reading from stdin, it use the InteractPipe """
            address = ql.reg.o1
            count = ql.reg.o2

            read = ql.stdin.read(count)
            if type(read) == type(""):
                read = read.encode("ascii") # ql.mem expect bytes, not str
            

            print('read({0:d}) = {1:s}'.format(count, repr(read)))


            ql.mem.write(address, read)
            ql.reg.o0 = len(read)

        def exit_hook(ql):
            print('exit')
            ql.emu_stop()

        def sleep_hook(ql):
            print('sleep()')        

        stdin = InteractPipe("0f0b00070346c83dde0001f9030100")

        # setup Qiling engine
        ql = Qiling(["../examples/rootfs/sparc_32/bin/sun_sat_sparc.elf"], "./",
            stdin=stdin,
            stdout=1,
            stderr=1,
            console=True,
            #output="disasm"
        )

        # hook everything we need
        hook_and_ret(ql, 0x40011EBC, puts_hook)
        hook_and_ret(ql, 0x40011D84, printf_hook)
        hook_and_ret(ql, 0x40003C9C, read_hook)
        hook_and_ret(ql, 0x40011860, exit_hook)
        hook_and_ret(ql, 0x40011FDC, sleep_hook)


        # now emulate the binary
        ql.run(
            begin = 0x4000145c, # Init function address
            end = 0x400014A8, # 0x40011860 # end of Init function address
        )
        

if __name__ == "__main__":
    unittest.main()
