from .loader import QlLoader
import magic

class QlLoaderDOS(QlLoader):
    def __init__(self, ql):
        super(QlLoaderDOS, self).__init__(ql)
        self.ql = ql

    def run(self):
        path = self.ql.path
        ftype = magic.from_file(path)

        if "COM" and "DOS" in ftype:
            # pure com
            self.cs = int(self.ql.profile.get("COM", "start_cs"), 16)
            self.ip = int(self.ql.profile.get("COM", "start_ip"), 16)
            self.ql.reg.ds = self.cs
            self.ql.reg.es = self.cs
            self.ql.reg.ss = self.cs
            self.ql.reg.ip = self.ip
            self.start_address = self.cs*16 + self.ip
            self.base_address = int(self.ql.profile.get("COM", "base_address"), 16)
            self.ql.mem.map(self.base_address, 64*1024)
            with open(path, "rb+") as f:
                bs = f.read()
            self.ql.mem.write(self.start_address, bs)
        elif "MS-DOS" in ftype:
            raise NotImplementedError()