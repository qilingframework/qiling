#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import pickle, sys, unittest

sys.path.append("..")
from qiling import Qiling
from qiling.extensions.sanitizers.heap import QlSanitizedMemoryHeap
from qiling.const import QL_INTERCEPT, QL_VERBOSE
from qiling.os.uefi import utils
from qiling.os.uefi.const import EFI_SUCCESS, EFI_INVALID_PARAMETER

ROOTFS_UEFI = r'../examples/rootfs/x8664_efi'

class Checklist:
    def __init__(self) -> None:
        self.visited_oncall  = False
        self.visited_onenter = False
        self.visited_onexit  = False

class Test_UEFI(unittest.TestCase):
    def test_x8664_uefi_santizier(self):
        def my_abort(msg: str):
            print(f"\n*** {msg} ***\n")

        def enable_sanitized_heap(ql: Qiling):
            heap = QlSanitizedMemoryHeap(ql, ql.os.heap, fault_rate=0)

            heap.oob_handler      = lambda *args: my_abort(f'Out-of-bounds read detected')
            heap.bo_handler       = lambda *args: my_abort(f'Buffer overflow/underflow detected')
            heap.bad_free_handler = lambda *args: my_abort(f'Double free or bad free detected')
            heap.uaf_handler      = lambda *args: my_abort(f'Use-after-free detected')

            # make sure future allocated buffers are not too close to UEFI data
            heap.alloc(0x1000)

            ql.os.heap = heap

        if __name__ == "__main__":
            env = {
                # the FaultType NVRAM variable is read by the executable to determine which
                # memory corruption it should trigger.
                #
                # fault types are:
                #   0 - POOL_OVERFLOW_MEMCPY
                #   1 - POOL_UNDERFLOW_MEMCPY
                #   2 - POOL_OVERFLOW_USER,
                #   3 - POOL_UNDERFLOW_USER
                #   4 - POOL_OOB_READ_AHEAD
                #   5 - POOL_OOB_READ_BEHIND
                #   6 - POOL_DOUBLE_FREE
                #   7 - POOL_INVALID_FREE
                'FaultType': bytes([1])
            }

            ql = Qiling([f'{ROOTFS_UEFI}/bin/EfiPoolFault.efi'], ROOTFS_UEFI, env=env, verbose=QL_VERBOSE.DEBUG)

            enable_sanitized_heap(ql)

            ql.run()

            self.assertFalse(ql.os.heap.validate(), 'expected heap corruption')

    def test_x8664_uefi(self):
        def force_notify_RegisterProtocolNotify(ql: Qiling, address: int, params):
            ql.log.info(f'[force_notify] address = {address:#x}, params = {params}')

            self.ck.visited_oncall = True

            event_id = params['Event']

            if event_id in ql.loader.events:
                event = ql.loader.events[event_id]

                # let's force notify
                event["Set"] = False

                utils.signal_event(ql, event_id)
                utils.execute_protocol_notifications(ql, True)

                return EFI_SUCCESS

            return EFI_INVALID_PARAMETER

        def my_onenter(ql: Qiling, address: int, params):
            ql.log.info(f'[my_onenter] address = {address:#x}, params = {params}')

            self.ck.visited_onenter = True

        def my_onexit(ql: Qiling, address: int, params, retval: int):
            ql.log.info(f'[my_onexit] address = {address:#x}, params = {params}')

            self.ck.visited_onexit = True

        if __name__ == "__main__":
            with open(f'{ROOTFS_UEFI}/rom2_nvar.pickel', 'rb') as f:
                env = pickle.load(f)

            ql = Qiling([f'{ROOTFS_UEFI}/bin/TcgPlatformSetupPolicy'], ROOTFS_UEFI, env=env, verbose=QL_VERBOSE.DEBUG)
            self.ck = Checklist()

            ql.os.set_api("RegisterProtocolNotify", force_notify_RegisterProtocolNotify)
            ql.os.set_api("CopyMem", my_onenter, QL_INTERCEPT.ENTER)
            ql.os.set_api("LocateProtocol", my_onexit, QL_INTERCEPT.EXIT)

            ql.run()

            self.assertTrue(self.ck.visited_oncall)
            self.assertTrue(self.ck.visited_onenter)
            self.assertTrue(self.ck.visited_onexit)

if __name__ == "__main__":
    unittest.main()
