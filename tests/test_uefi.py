#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys,unittest
import pickle
sys.path.append("..")
from qiling import *
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
            if event_id in ql.loader.events:
                ql.loader.events[event_id]['Guid'] = params["Protocol"]
                # let's force notify
                event = ql.loader.events[event_id]
                event["Set"] = True
                ql.loader.notify_list.append((event_id, event['NotifyFunction'], event['NotifyContext']))
                ######
                return EFI_SUCCESS
            return EFI_INVALID_PARAMETER


        if __name__ == "__main__":
            with open("../examples/rootfs/x8664_efi/rom2_nvar.pickel", 'rb') as f:
                env = pickle.load(f)
            ql = Qiling(["../examples/rootfs/x8664_efi/bin/TcgPlatformSetupPolicy"], "../examples/rootfs/x8664_efi", env=env, output="debug")
            ql.set_api("hook_RegisterProtocolNotify", force_notify_RegisterProtocolNotify)
            ql.run()

if __name__ == "__main__":
    unittest.main()
