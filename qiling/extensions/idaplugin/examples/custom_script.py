from qiling import *

def get_ql_base_address(ql:Qiling):
    if ql.archbit == 32:
        return int(ql.profile.get("OS32", "load_address"), 16)
    elif ql.archbit == 64:
        return int(ql.profile.get("OS64", "load_address"), 16)

class QL_CUSTOM_SCRIPT():
    def __init__(self):
        self.stepflag = True

    def ql_custom_continue(self, ql:Qiling):
        def continue_hook(ql, addr, size):
            print(hex(addr))

        print('user continue hook')
        hook = []
        hook.append(ql.hook_code(continue_hook))
        return hook

    def ql_custom_step(self, ql:Qiling):
        def step_hook1(ql, addr, size):
            print(hex(addr))

        def step_hook2(ql):
            self.stepflag = not self.stepflag
            if self.stepflag:
                print('arrive to 0x52A')

        print('user step hook')
        hook = []
        hook.append(ql.hook_code(step_hook1))
        hook.append(ql.hook_address(step_hook2, 0x52A+get_ql_base_address(ql)))
        return hook
