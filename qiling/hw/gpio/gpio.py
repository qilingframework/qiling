from qiling.hw.peripheral import QlPeripheral


class BaseGPIO(QlPeripheral):
    def __init__(self, ql, tag, **kwargs):
        super().__init__(ql, tag, **kwargs)
        self.states = []

    
    def reset(self):
        for i in self.states:
            self.states[i] = False

    def connect(self):
        pass

    def disconnect(self):
        pass

