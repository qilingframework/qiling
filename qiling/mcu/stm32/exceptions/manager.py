from .system_tick import SystemTickException

class ExceptionManager:
    def __init__(self, arch):
        self.arch = arch
        
        self.systick = SystemTickException(self.arch)

    def interrupt(self):
        self.systick.handle()