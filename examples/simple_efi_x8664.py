#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import pickle

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_INTERCEPT, QL_VERBOSE
from qiling.os.uefi.const import EFI_SUCCESS, EFI_INVALID_PARAMETER
from qiling.os.uefi.utils import check_and_notify_protocols, signal_event

def force_notify_RegisterProtocolNotify(ql: Qiling, address: int, params):
    event_id = params['Event']

    if event_id in ql.loader.events:
        # let's force notify
        event = ql.loader.events[event_id]
        event['Guid'] = params["Protocol"]
        event["Set"] = False

        signal_event(ql, event_id)
        check_and_notify_protocols(ql, True)

        return EFI_SUCCESS

    return EFI_INVALID_PARAMETER

def my_onenter(ql: Qiling, address: int, params):
    print(f'[onenter] CopyMem : params = {params}')

    return address, params

if __name__ == "__main__":
    with open("rootfs/x8664_efi/rom2_nvar.pickel", 'rb') as f:
        env = pickle.load(f)

    ql = Qiling(["rootfs/x8664_efi/bin/TcgPlatformSetupPolicy"], "rootfs/x8664_efi", env=env, verbose=QL_VERBOSE.DEBUG)

    ql.set_api("RegisterProtocolNotify", force_notify_RegisterProtocolNotify)
    ql.set_api("CopyMem", my_onenter, QL_INTERCEPT.ENTER)

    ql.run()
