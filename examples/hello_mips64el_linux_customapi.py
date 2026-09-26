#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# NOTE: this runs a dynamically-linked glibc MIPS64 (n64, little-endian) binary,
# which links above the 2GB useg and uses ll/sc locks. It requires the MIPS64
# virtual-TLB fixes in unicorn (https://github.com/unicorn-engine/unicorn issues
# #2272 / the ll-AdEL fix); on an unfixed unicorn it raises a spurious RI/AdEL.

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.os.const import STRING
from qiling.const import QL_VERBOSE

def my_puts(ql: Qiling):
    params = ql.os.resolve_fcall_params({'s': STRING})

    print(f'puts("{params["s"]}")')

if __name__ == "__main__":
    ql = Qiling(["rootfs/mips64el_linux/bin/mips64el_hello"], "rootfs/mips64el_linux", verbose=QL_VERBOSE.DEBUG)
    ql.os.set_api("puts", my_puts)
    ql.run()
