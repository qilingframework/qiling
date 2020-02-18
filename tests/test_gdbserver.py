from qiling import *


def test_gdb_x86():
    ql = Qiling(["./examples/rootfs/x86_windows/bin/x86_hello.exe"], "./examples/rootfs/x86_windows/bin")
    ql.gdb = ":9999"
    ql.run()

def test_gdb_x8664():
    ql = Qiling(["./examples/rootfs/x8664_windows/bin/x8664_hello.exe"], "./examples/rootfs/x8664_windows/bin")
    ql.gdb = ":9999"
    ql.run()


if __name__ == "__main__":
    test_gdb_x86()
    test_gdb_x8664()
