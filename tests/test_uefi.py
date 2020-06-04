#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys,unittest
import pickle
sys.path.append("..")
from qiling import *
from qiling.const import *
from qiling.exception import *
from qiling.os.uefi.const import *
from qiling.os.const import *

class Test_UEFI(unittest.TestCase):
    def test_x8664_uefi(self):
        def force_notify_RegisterProtocolNotify(ql, address, params):
            print("\n")
            print("=" * 40)
            print(" Enter into set_api mode")
            print("=" * 40)
            print("\n")
            event_id = params['Event']
            self.set_api = "pass"
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
            self.set_api_onenter = "pass"
            return address, params

        def my_onexit(ql, address, params):
            print("\n")
            print("=" * 40)
            print(" Enter into my_exit mode")
            print("params: %s" % params)
            print("=" * 40)
            print("\n")
            self.set_api_onexit = "pass"


        if __name__ == "__main__":
            with open("../examples/rootfs/x8664_efi/rom2_nvar.pickel", 'rb') as f:
                env = pickle.load(f)
            ql = Qiling(["../examples/rootfs/x8664_efi/bin/TcgPlatformSetupPolicy"], "../examples/rootfs/x8664_efi", env=env, output="debug")
            ql.set_api("RegisterProtocolNotify", force_notify_RegisterProtocolNotify)
            ql.set_api("CopyMem", my_onenter)
            ql.set_api("LocateProtocol", my_onexit)
            ql.run()

            self.assertEqual("pass", self.set_api)
            self.assertEqual("pass", self.set_api_onenter)
            self.assertEqual("pass", self.set_api_onexit)
            
            del ql
            del self.set_api
            del self.set_api_onenter
            del self.set_api_onexit

if __name__ == "__main__":
    unittest.main()
