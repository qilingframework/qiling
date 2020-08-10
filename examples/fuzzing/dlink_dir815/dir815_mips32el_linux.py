#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

# Everything about the bug and firmware https://www.exploit-db.com/exploits/33863

import os,sys

# This is new. Instead of unicorn, we import unicornafl. It's the same Uc with some new `afl_` functions
import unicornafl

# Make sure Qiling uses our patched unicorn instead of it's own, second so without instrumentation!
unicornafl.monkeypatch()

sys.path.append("../../..")
from qiling import *


def main(input_file, enable_trace=False):
    
    env_vars = {
        "REQUEST_METHOD": "POST",
        "REQUEST_URI": "/hedwig.cgi",
        "CONTENT_TYPE": "application/x-www-form-urlencoded",
        "REMOTE_ADDR": "127.0.0.1",
        "HTTP_COOKIE": "uid=1234&password="+"A" * 0x1000,  # fill up
        # "CONTENT_LENGTH": "8", # no needed
    }

    ql = Qiling(["./rootfs/htdocs/web/hedwig.cgi"], "./rootfs",
                output="debug", env=env_vars,
                console = True if enable_trace else False)
    
    def place_input_callback(uc, input, _, data):
        env_var = ("HTTP_COOKIE=uid=1234&password=").encode()
        env_vars = env_var + input + b"\x00" + (ql.path).encode() + b"\x00"
        ql.mem.write(ql.target_addr, env_vars)


    def start_afl(_ql: Qiling):

        """
        Callback from inside
        """
        # We start our AFL forkserver or run once if AFL is not available.
        # This will only return after the fuzzing stopped.
        try:
            print("Starting afl_fuzz().")
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

    addr = ql.mem.search("HTTP_COOKIE=uid=1234&password=".encode())
    ql.target_addr = addr[0]

    main_addr = ql.os.elf_entry
    ql.hook_address(callback=start_afl, address=main_addr)

    try:
        ql.run()
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
