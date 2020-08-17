from qiling import *

class QL_CUSTOM_SCRIPT():
    def __init__(self):
        pass

    def ql_continue_hook_add(self, ql:Qiling):
        def continue_hook(ql, addr, size):
            print(hex(addr))
        print('user continue hook')
        hook = ql.hook_code(continue_hook)
        return hook

    def ql_step_hook_add(self, ql:Qiling):
        def step_hook(ql, addr, size):
            print(hex(addr))
        print('user step hook')
        hook = ql.hook_code(step_hook)
        return hook
