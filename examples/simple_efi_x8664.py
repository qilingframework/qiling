#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
import pickle
sys.path.append("..")
from qiling import *
from qiling.const import *
from qiling.os.uefi.const import *
from qiling.os.uefi.utils import execute_protocol_notifications

def force_notify_RegisterProtocolNotify(ql, address, params):
    event_id = params['Event']
    if event_id in ql.loader.events:
        ql.loader.events[event_id]['Guid'] = params["Protocol"]
        # let's force notify
        event = ql.loader.events[event_id]
        event["Set"] = True
        ql.loader.notify_list.append((event_id, event['NotifyFunction'], event['CallbackArgs']))
        execute_protocol_notifications(ql, True)
        ######
        return EFI_SUCCESS
    return EFI_INVALID_PARAMETER

def my_onenter(ql, param_num, params):
    print("\n")
    print("=" * 40)
    print(" Enter into my_onenter mode")
    print("=" * 40)
    print("\n")
    return param_num, params


if __name__ == "__main__":
    with open("rootfs/x8664_efi/rom2_nvar.pickel", 'rb') as f:
        env = pickle.load(f)
    ql = Qiling(["rootfs/x8664_efi/bin/TcgPlatformSetupPolicy"], "rootfs/x8664_efi", env=env, output="debug")
    ql.set_api("RegisterProtocolNotify", force_notify_RegisterProtocolNotify)
    ql.set_api("CopyMem", my_onenter, QL_INTERCEPT.ENTER)
    ql.run()