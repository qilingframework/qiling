#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# Everything about the bug and firmware https://www.exploit-db.com/exploits/33863

import os,sys
sys.path.append("../../..")

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.afl import ql_afl_fuzz


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
                verbose=QL_VERBOSE.DEBUG, env=env_vars, console=enable_trace)

    def place_input_callback(ql: Qiling, input: bytes, _: int):
        env_var = ("HTTP_COOKIE=uid=1234&password=").encode()
        env_vars = env_var + input + b"\x00" + (ql.path).encode() + b"\x00"
        ql.mem.write(ql.target_addr, env_vars)

    def start_afl(_ql: Qiling):

        """
        Callback from inside
        """
        ql_afl_fuzz(_ql, input_file=input_file, place_input_callback=place_input_callback, exits=[ql.os.exit_point])

    addr = ql.mem.search("HTTP_COOKIE=uid=1234&password=".encode())
    ql.target_addr = addr[0]

    main_addr = ql.loader.elf_entry
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
