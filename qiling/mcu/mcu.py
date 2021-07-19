from unicorn import Uc

class QlMcu(Uc):
    def __init__(self, ql, arch, mode):
        super().__init__(arch, mode)
        self.ql = ql

    def flash(self):
        self.ql.loader.run()

    @property
    def reg(self):
        return self.ql.reg
    
    @property
    def mem(self):
        return self.ql.mem

    @property
    def pc(self):
        return self.reg.read('pc')

    @property
    def lr(self):
        return self.reg.read('lr')