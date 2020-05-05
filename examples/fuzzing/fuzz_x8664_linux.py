#!/usr/bin/env python3
"""
Simple example of how to use Qiling together with AFLplusplus.
This is tested with the recent Qiling framework (the one you cloned),
afl++ from https://github.com/AFLplusplus/AFLplusplus

After building afl++, make sure you install `unicorn_mode/setup_unicorn.sh`

Then, run this file using afl++ unicorn mode with
afl-fuzz -i ./afl_inputs -o ./afl_outputs -m none -U -- python3 ./fuzz_x8664_linux.py @@
"""

# This is new. Instead of unicorn, we import unicornafl. It's the same Uc with some new `afl_` functions
import unicornafl

# Make sure Qiling uses our patched unicorn instead of it's own, second so without instrumentation!
unicornafl.monkeypatch()

import sys, os
from binascii import hexlify

from capstone.x86_const import *

sys.path.append("../..")
from qiling import *

# we cache this for some extra speed
stdin_fstat = os.fstat(sys.stdin.fileno())

# This is mostly taken from the crackmes
class MyPipe():
    def __init__(self):
        self.buf = b''

    def write(self, s):
        self.buf += s

    def read(self, size):
        if size <= len(self.buf):
            ret = self.buf[: size]
            self.buf = self.buf[size:]
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

    def fstat(self):
        return stdin_fstat


def main(input_file, enable_trace=False):
    stdin = MyPipe()
    ql = Qiling(["./x8664_fuzz"], "../rootfs/x8664_linux",
                stdin=stdin,
                stdout=1 if enable_trace else None,
                stderr=1 if enable_trace else None,
                log_console = True if enable_trace else False)

    # or this for output:
    # ... stdout=sys.stdout, stderr=sys.stderr)

    def place_input_callback(uc, input, _, data):
        stdin.write(input)

    def start_afl(_ql: Qiling):
        """
        Callback from inside
        """
        # We start our AFL forkserver or run once if AFL is not available.
        # This will only return after the fuzzing stopped.
        try:
            #print("Starting afl_fuzz().")
            if not _ql.uc.afl_fuzz(input_file=input_file,
                        place_input_callback=place_input_callback,
                        exits=[ql.os.exit_point]):
                print("Ran once without AFL attached.")
                os._exit(0)  # that's a looot faster than tidying up.
        except unicornafl.UcAflError as ex:
            # This hook trigers more than once in this example.
            # If this is the exception cause, we don't care.
            # TODO: Chose a better hook position :)
            if ex != unicornafl.UC_AFL_RET_CALLED_TWICE:
                raise
    
    # 64 bit loader addrs are placed at 0x7ffbf0100000
    # see loader/elf.py:load_with_ld(..)
    X64BASE = int(ql.profile.get("OS64", "load_address"),16)
    
    # crash in case we reach stackcheck_fail:
    # 1225:	e8 16 fe ff ff       	callq  1040 <__stack_chk_fail@plt>
    ql.hook_address(callback=lambda x: os.abort(), address=X64BASE + 0x1225)

    # Add hook at main() that will fork Unicorn and start instrumentation.
    # main starts at X64BASE + 0x122c
    main_addr = X64BASE + 0x122c
    ql.hook_address(callback=start_afl, address=main_addr)

    if enable_trace:
        # The following lines are only for `-t` debug output

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        count = [0]

        def spaced_hex(data):
            return b' '.join(hexlify(data)[i:i+2] for i in range(0, len(hexlify(data)), 2)).decode('utf-8')

        def disasm(count, ql, address, size):
            buf = ql.mem.read(address, size)
            try:
                for i in md.disasm(buf, address):
                    return "{:08X}\t{:08X}: {:24s} {:10s} {:16s}".format(count[0], i.address, spaced_hex(buf), i.mnemonic,
                                                                        i.op_str)
            except:
                import traceback
                print(traceback.format_exc())

        def trace_cb(ql, address, size, count):
            rtn = '{:100s}'.format(disasm(count, ql, address, size))
            print(rtn)
            count[0] += 1

        ql.hook_code(trace_cb, count)

    # okay, ready to roll.
    # try:
    ql.run()
    # except Exception as ex:
    #     # Probable unicorn memory error. Treat as crash.
    #     print(ex)
    #     os.abort()

    os._exit(0)  # that's a looot faster than tidying up.


if __name__ == "__main__":
    if len(sys.argv) == 1:
        raise ValueError("No input file provided.")
    if len(sys.argv) > 2 and sys.argv[1] == "-t":
        main(sys.argv[2], enable_trace=True)
    else:
        main(sys.argv[1])
