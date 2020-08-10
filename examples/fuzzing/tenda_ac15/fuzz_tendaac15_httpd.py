#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


# 1. Download AC15 Firmware from https://down.tenda.com.cn/uploadfile/AC15/US_AC15V1.0BR_V15.03.05.19_multi_TD01.zip
# 2. unzip
# 3. binwalk -e US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin
# 4. locate squashfs-root
# 5. rm -rf webroot && mv webroot_ro webroot
#

import os, pickle, socket, sys, threading

import unicornafl
unicornafl.monkeypatch()

sys.path.append("../../../")
from qiling import *


def patcher(ql):
    br0_addr = ql.mem.search("br0".encode() + b'\x00')
    for addr in br0_addr:
        ql.mem.write(addr, b'lo\x00')


def main(input_file, enable_trace=False):
    ql = Qiling(["rootfs/bin/httpd"], "rootfs", output = "debug", console = True if enable_trace else False)

    # save current emulated status
    ql.restore(snapshot="snapshot.bin")

    # return should be 0x7ff3ca64
    fuzz_mem=ql.mem.search(b"CCCCAAAA")
    target_address = fuzz_mem[0]

    def place_input_callback(uc, input, _, data):
        ql.mem.write(target_address, input)

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

    ql.hook_address(callback=start_afl, address=0x10930+8)
    
    try:
        ql.run(begin = 0x10930+4, end = 0x7a0cc+4)
        os._exit(0)
    except:
        if enable_trace:
            print("\nFuzzer Went Shit")
        os._exit(0)        

if __name__ == "__main__":
    if len(sys.argv) == 1:
        raise ValueError("No input file provided.")

    if len(sys.argv) > 2 and sys.argv[1] == "-t":
        main(sys.argv[2], enable_trace=True)
    else:
        main(sys.argv[1])
