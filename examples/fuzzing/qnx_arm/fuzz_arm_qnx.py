#!/usr/bin/env python3
"""
Simple example of how to use Qiling together with AFLplusplus.
This is tested with the recent Qiling framework (the one you cloned),
afl++ from https://github.com/AFLplusplus/AFLplusplus

After building afl++, make sure you install `unicorn_mode/setup_unicorn.sh`

Then, run this file using afl++ unicorn mode with
afl-fuzz -i ./afl_inputs -o ./afl_outputs -m none -U -- python3 ./fuzz_x8664_linux.py @@
"""

# No more need for importing unicornafl, try ql.afl_fuzz instead!

import sys, os
from binascii import hexlify

sys.path.append("../../..")
from qiling import *
from qiling.extensions import pipe
from qiling.extensions.afl import ql_afl_fuzz

def main(input_file, enable_trace=False):
    ql = Qiling(["./arm_fuzz"], "../../rootfs/arm_qnx", console=enable_trace)

    ql.os.stdin = pipe.SimpleInStream(sys.stdin.fileno())

    if not enable_trace:
        ql.os.stdout = pipe.NullOutStream(sys.stdout.fileno())
        ql.os.stderr = pipe.NullOutStream(sys.stderr.fileno())

    def place_input_callback(ql: Qiling, input: bytes, _: int):
        ql.os.stdin.write(input)
        return True

    def start_afl(_ql: Qiling):
        ql_afl_fuzz(_ql, input_file=input_file, place_input_callback=place_input_callback, exits=[ql.os.exit_point])

    LIBC_BASE = int(ql.profile.get("OS32", "interp_address"), 16)

    # crash in case we reach SignalKill
    ql.hook_address(callback=lambda x: os.abort(), address=LIBC_BASE + 0x38170)

    # Add hook at main() that will fork Unicorn and start instrumentation.
    main_addr = 0x08048aa0
    ql.hook_address(callback=start_afl, address=main_addr)

    if enable_trace:
        # The following lines are only for `-t` debug output
        md = ql.arch.disassembler
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
