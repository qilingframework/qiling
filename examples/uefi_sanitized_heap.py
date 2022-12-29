#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
import sys

sys.path.append("..")
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.sanitizers.heap import QlSanitizedMemoryHeap

def my_abort(msg):
    print(f"\n*** {msg} ***\n")
    os.abort()

def enable_sanitized_heap(ql, fault_rate=0):
    heap = QlSanitizedMemoryHeap(ql, ql.os.heap, fault_rate=fault_rate)

    heap.oob_handler      = lambda *args: my_abort(f'Out-of-bounds read detected')
    heap.bo_handler       = lambda *args: my_abort(f'Buffer overflow/underflow detected')
    heap.bad_free_handler = lambda *args: my_abort(f'Double free or bad free detected')
    heap.uaf_handler      = lambda *args: my_abort(f'Use-after-free detected')

    # make sure future allocated buffers are not too close to UEFI data
    heap.alloc(0x1000)

    ql.os.heap = heap
    ql.loader.dxe_context.heap = heap

def sanitized_emulate(path, rootfs, fault_type, verbose=QL_VERBOSE.DEBUG):
    env = {'FaultType': fault_type}
    ql = Qiling([path], rootfs, env=env, verbose=verbose)

    enable_sanitized_heap(ql)
    ql.run()

    if not ql.os.heap.validate():
        my_abort("Canary corruption detected")

def usage():
    print("""
Usage: ./uefi_santizied_heap.py <fault-type>
Valid fault types:
0 - POOL_OVERFLOW_MEMCPY
1 - POOL_UNDERFLOW_MEMCPY
2 - POOL_OVERFLOW_USER
3 - POOL_UNDERFLOW_USER
4 - POOL_OOB_READ_AHEAD
5 - POOL_OOB_READ_BEHIND
6 - POOL_DOUBLE_FREE
7 - POOL_INVALID_FREE
""")
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    fault_type = bytes([int(sys.argv[1])])
    rootfs = os.path.join(os.getcwd(), 'rootfs', 'x8664_efi')
    path = os.path.join(rootfs, 'bin', 'EfiPoolFault.efi')

    sanitized_emulate(path, rootfs, fault_type, verbose=QL_VERBOSE.DEBUG)
