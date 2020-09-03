from qiling.const import QL_OS


class Report:
    def __init__(self, ql):
        self.filename = ql.filename
        self.rootfs = ql.rootfs
        self.arch = ql.archtype
        self.os = ql.ostype
        self.env = ql.env
        self.strings = set()
        for string in ql.os.appeared_strings:
            strings = string.split(" ")
            self.strings |= set(strings)
        self.profile = ql.profile
        self.patches = []
        self.patches.extend(ql.patch_bin)
        self.patches.extend(ql.patch_lib)

    def to_dict(self):
        res = {}
        for key in self.__dict__:
            res[key] = self.__dict__[key]
        return res


class WindowsReport(Report):
    def __init__(self, ql):
        super().__init__(ql)
        self.dlls = ql.loader.dlls
        self.teb = ql.loader.TEB.base
        self.peb = ql.loader.PEB.base
        self.ldr = ql.loader.LDR.base
        self.api = ql.os.syscalls
        self.registries = {}
        for key, values in ql.os.registry_manager.accessed.items():
            self.registries[key] = values
        self.entry_point = ql.loader.entry_point
        self.import_symbols = ql.loader.import_symbols
        self.export_symbols = ql.loader.export_symbols
        self.cmdline = ql.loader.cmdline


def make_report(ql) -> dict:
    if ql.ostype == QL_OS.WINDOWS:
        report = WindowsReport(ql)
    else:
        report = Report(ql)
    return report.to_dict()
