#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import afl, os, sys
from underflow_test import underflow

afl.init()

sys.stdin.seek(0)
in_str = sys.stdin.read().strip()

if in_str.isdigit():
    fuzz_value = int(in_str)
    underflow(fuzz_value)

os._exit(0)