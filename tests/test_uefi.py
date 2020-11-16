#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import os, pickle, sys,unittest
sys.path.append("..")
from qiling import *
from qiling.extensions.sanitizers.heap import QlSanitizedMemoryHeap
from qiling.const import *
from qiling.exception import *
from qiling.os.uefi.const import *
from qiling.os.const import *

class Test_UEFI(unittest.TestCase):
    def test_x8664_uefi_santizier(self):
        def my_abort(msg):
            print(f"\n*** {msg} ***\n")

        def enable_sanitized_heap(ql, fault_rate=0):
            ql.os.heap = QlSanitizedMemoryHeap(ql, ql.os.heap)
            ql.os.heap.pool_fault_rate = fault_rate
            ql.os.heap.oob_handler = lambda *args: my_abort("Out-of-bounds read detected")
            ql.os.heap.bo_handler = lambda *args: my_abort("Buffer overflow/underflow detected")
            ql.os.heap.bad_free_handler = lambda *args: my_abort("Double free or bad free detected")
            ql.os.heap.uaf_handler = lambda *args: my_abort("Use-after-free detected")

        def sanitized_emulate(path, rootfs, fault_type, output="debug", enable_trace=False):
            ql = Qiling([path], rootfs, output=output)
            ql.env['FaultType'] = fault_type
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
        2 - POOL_OVERFLOW_USER,
        3 - POOL_UNDERFLOW_USER
        4 - POOL_OOB_READ_AHEAD
        5 - POOL_OOB_READ_BEHIND
        6 - POOL_DOUBLE_FREE
        7 - POOL_INVALID_FREE
        """)
            sys.exit(0)

        fault_type = bytes([int(1)])
        rootfs = "../examples/rootfs/x8664_efi"
        path = "../examples/rootfs/x8664_efi/bin/EfiPoolFault.efi"
        sanitized_emulate(path, rootfs, fault_type, output='debug', enable_trace=True)

    def test_x8664_uefi(self):
        def force_notify_RegisterProtocolNotify(ql, address, params):
            print("\n")
            print("=" * 40)
            print(" Enter into set_api mode")
            print("=" * 40)
            print("\n")
            event_id = params['Event']
            self.set_api = event_id
            if event_id in ql.loader.events:
                ql.loader.events[event_id]['Guid'] = params["Protocol"]
                # let's force notify
                event = ql.loader.events[event_id]
                event["Set"] = True
                ql.loader.notify_list.append((event_id, event['NotifyFunction'], event['NotifyContext']))
                ######
                return EFI_SUCCESS
            return EFI_INVALID_PARAMETER

        def my_onenter(ql, address, params):
            print("\n")
            print("=" * 40)
            print(" Enter into my_onenter mode")
            print(params)
            print("=" * 40)
            print("\n")
            self.set_api_onenter = params["Source"]
            return address, params

        def my_onexit(ql, address, params):
            print("\n")
            print("=" * 40)
            print(" Enter into my_exit mode")
            print("params: %s" % params)
            print("=" * 40)
            print("\n")
            self.set_api_onexit = params["Registration"]


        if __name__ == "__main__":
            with open("../examples/rootfs/x8664_efi/rom2_nvar.pickel", 'rb') as f:
                env = pickle.load(f)
            ql = Qiling(["../examples/rootfs/x8664_efi/bin/TcgPlatformSetupPolicy"], "../examples/rootfs/x8664_efi", env=env, output="debug")
            ql.set_api("RegisterProtocolNotify", force_notify_RegisterProtocolNotify)
            ql.set_api("CopyMem", my_onenter, QL_INTERCEPT.ENTER)
            ql.set_api("LocateProtocol", my_onexit, QL_INTERCEPT.EXIT)
            ql.run()

            self.assertEqual(0, self.set_api)
            self.assertEqual(21475885153, self.set_api_onenter)
            self.assertEqual(0, self.set_api_onexit)
            
            del ql
            del self.set_api
            del self.set_api_onenter
            del self.set_api_onexit

if __name__ == "__main__":
    unittest.main()
