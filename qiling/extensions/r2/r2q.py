from qiling import Qiling
from .mem import R2Mem
from .r2 import R2


class R2Qiling(Qiling):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._mem = R2Mem(self.mem)
        self.r2 = R2(self)