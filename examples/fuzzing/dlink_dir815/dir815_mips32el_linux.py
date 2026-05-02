#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# Everything about the bug and firmware https://www.exploit-db.com/exploits/33863

import sys
sys.path.append("../../..")

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.afl import ql_afl_fuzz


def main(input_file: str):

    env_vars = {
        "REQUEST_METHOD": "POST",
        "REQUEST_URI": "/hedwig.cgi",
        "CONTENT_TYPE": "application/x-www-form-urlencoded",
        "REMOTE_ADDR": "127.0.0.1",
        "HTTP_COOKIE": "uid=1234&password="+"A" * 0x1000,  # fill up
        # "CONTENT_LENGTH": "8", # no needed
    }

    ql = Qiling(["./rootfs/htdocs/web/hedwig.cgi"], "./rootfs", verbose=QL_VERBOSE.DISABLED, env=env_vars)

    def place_input_callback(ql: Qiling, data: bytes, _: int) -> bool:
        # construct the payload
        payload = b''.join((b"HTTP_COOKIE=uid=1234&password=", bytes(data), b"\x00", ql_path, b"\x00"))

        # patch the value of 'HTTP_COOKIE' in memory
        ql.mem.write(target_addr, payload)

        # payload is in place, we are good to go
        return True

    def start_afl(_ql: Qiling):
        """
        Callback from inside
        """

        ql_afl_fuzz(_ql, input_file=input_file, place_input_callback=place_input_callback, exits=[ql.os.exit_point])

    addr = ql.mem.search(b"HTTP_COOKIE=uid=1234&password=")
    target_addr = addr[0]
    ql_path = ql.path.encode()

    ql.hook_address(start_afl, ql.loader.elf_entry)

    ql.run()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise ValueError("No input file provided.")

    main(sys.argv[1])
