from qiling import *

def get_ql_base_address(ql:Qiling):
    if ql.archbit == 32:
        return int(ql.profile.get("OS32", "load_address"), 16)
    elif ql.archbit == 64:
        return int(ql.profile.get("OS64", "load_address"), 16)

class QILING_IDA():
    def __init__(self):
        pass

    def custom_continue(self, ql:Qiling):
        def continue_hook(ql, addr, size):
            print(hex(addr))

        print('user continue hook')
        hook = []
        hook.append(ql.hook_code(continue_hook))
        return hook

    def custom_step(self, ql:Qiling, stepflag):
        def step_hook1(ql, addr, size, stepflag):
            if stepflag:
                stepflag = not stepflag
                print(hex(addr))

        def step_hook2(ql):
            print('arrive to 0x52A')

        print('user step hook')
        hook = []
        hook.append(ql.hook_code(step_hook1, user_data=stepflag))
        hook.append(ql.hook_address(step_hook2, 0x52A+get_ql_base_address(ql)))
        return hook
