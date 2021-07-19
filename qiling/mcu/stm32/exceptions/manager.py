from .system_tick import SystemTickException

class ExceptionManager:
    def __init__(self, mcu):
        self.mcu = mcu
        
        self.systick = SystemTickException(self.mcu)

    def interrupt(self):
        self.systick.handle()