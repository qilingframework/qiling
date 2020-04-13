#### Options for output

```
output = ("off", "default", "disasm", "debug", "dump")
    off: no output, except fatal error
    default: unix strace type or ltrace typpe for windows
    disasm: disasmembler output
    debug: disasmembler, block trace, all errors
    dump: disasmembler with block trace and also key CPU register output
```

#### Options for Console Log

```
log_console = (True, False)
    Normally this option will be used with log_dir
        case 1: log_dir defined and log_console is False
            - No stdio output
        case 2: log_dir defined and log_console is True
            - Log dump to folder and also print stdio
```

---

#### Examples

- How to run Netgear R6220 Firmware with
    - ql.add_fs_mapper, "host File System Mapping"
    - log_dir redirect logs to defined folder
    - log_console stdio display
    - ql.root, avoid host root privillage requirement and return to userland

```python
import sys
from qiling import *

def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, output="debug", log_dir = 'qlog', log_console = True)
    ql.log_split= True,
    ql.root = False
    ql.add_fs_mapper('/proc', '/proc')
    ql.run()

if __name__ == "__main__":
    my_sandbox(["rootfs/netgear_r6220/bin/mini_httpd","-d","/www","-r","NETGEAR R6220","-c","**.cgi","-t","300"], "rootfs/netgear_r6220")
```



- How to emulate a Windows EXE on a Linux machine

```python
from qiling import *

def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs)
    ql.run()

if __name__ == "__main__":
    # execute Windows EXE under our rootfs
    my_sandbox(["examples/rootfs/x86_windows/bin/x86-windows-hello.exe"], "examples/rootfs/x86_windows")
```

- How to dynamically patch a Windows binary to make sure always pwn3d

```python
from qiling import *

def force_call_dialog_func(ql):
    # get DialogFunc address
    lpDialogFunc = ql.unpack32(ql.mem.read(ql.reg.sp - 0x8, 4))
    # setup stack for DialogFunc
    ql.stack_push(0)
    ql.stack_push(1001)
    ql.stack_push(273)
    ql.stack_push(0)
    ql.stack_push(0x0401018)
    # force EIP to DialogFunc
    ql.reg.pc = lpDialogFunc


def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs)
    ql.patch(0x004010B5, b'\x90\x90')
    ql.patch(0x004010CD, b'\x90\x90')
    ql.patch(0x0040110B, b'\x90\x90')
    ql.patch(0x00401112, b'\x90\x90')
    ql.hook_address(force_call_dialog_func, 0x00401016)
    ql.run()


if __name__ == "__main__":
    my_sandbox(["rootfs/x86_windows/bin/Easy_CrackMe.exe"], "rootfs/x86_windows")
```

#### Qltool

Qiling also provides a friendly tool named `qltool` to quickly emulate shellcode & executable binaries.

To emulate a binary, run:

```
$ ./qltool run -f examples/rootfs/arm_linux/bin/arm-hello --rootfs examples/rootfs/arm_linux/

```

To run shellcode, run:

```
$ ./qltool shellcode --os linux --arch x86 --asm -f examples/shellcodes/lin32_execve.asm

```
