Qiling - Advanced Binary Emulation framework
---

<p align="center">
<img width="150" height="150" src="docs/qiling_small.png">
</p>

Qiling is an advanced binary emulation framework, with the following features:

- Cross platform: Windows, MacOS, Linux, BSD
- Cross architecture: X86, X86_64, Arm, Arm64, Mips
- Multiple file formats: PE, MachO, ELF
- Emulate & sandbox machine code in a isolated enviroment
- Provide high level API to setup & configure the sandbox
- Fine-grain instrumentation: allow hooks at various levels (instruction/basic-block/memory-access/exception/syscall/IO/etc)
- Allow dynamic hotpatch on-the-fly running code, including the loaded library
- True framework in Python, make it easy to build customized security analysis tools on top

Qiling is backed by [Unicorn engine](www.unicorn-engine.org).

Visit our website https://www.qiling.io for more information.

---

#### Announcement

We are currently in Alpha test phase, that will be followed by public beta release.

This is a call for testers: please email your short instroduction, with github/gitlab ID to info@qiling.io for shortlisting.

Evaluation will be based on your open source participation.

---

#### Install

Run below command line to install Qiling (NOTE: you may need sudo on your platform to install to system directory).

```
python3 setup.py install
```

---

#### Examples

- Below example shows how to use Qiling framework to emulate a Windows EXE on a Linux machine.

```python
from qiling import *

# sandbox to emulate the EXE
def my_sandbox(path, rootfs):
    # setup Qiling engine
    ql = Qiling(path, rootfs)
    # now emulate the EXE
    ql.run()

if __name__ == "__main__":
    # execute Windows EXE under our rootfs
    my_sandbox(["examples/rootfs/x86_windows/bin/x86-windows-hello.exe"], "examples/rootfs/x86_windows")
```

- Below example shows how to use Qiling framework to dynamically patch a Windows crackme, make it always display "Congratulation" dialog.

```python
from unicorn.x86_const import *
from qiling import *

# callback for code instrumentation
def force_call_dialog_func(uc, address, size, ql):
    if address == 0x00401016:
        # get address of DialogFunc()
        lpDialogFunc = ql.unpack32(uc.mem_read(uc.reg_read(UC_X86_REG_ESP) - 0x8, 4))

        # setup stack for DialogFunc()
        ql.stack_push(uc, 0)
        ql.stack_push(uc, 1001)
        ql.stack_push(uc, 273)
        ql.stack_push(uc, 0)
        ql.stack_push(uc, 0x0401018)

        # point EIP to DialogFunc()
        ql.uc.reg_write(UC_X86_REG_EIP, lpDialogFunc)

# sandbox to emulate the EXE
def my_sandbox(path, rootfs, ostype):
    # setup Qiling engine
    ql = Qiling(path, rootfs, ostype = ostype)

    # NOP out some code
    ql.patch(0x004010B5, b'\x90\x90')
    ql.patch(0x004010CD, b'\x90\x90')
    ql.patch(0x0040110B, b'\x90\x90')
    ql.patch(0x00401112, b'\x90\x90')

    # instrument every instruction with callback force_call_dialog_func
    ql.hook_code(force_call_dialog_func, ql)

    # now emulate the binary
    ql.run()

if __name__ == "__main__":
    my_sandbox(["examples/rootfs/x86_windows/bin/Easy_CrackMe.exe"], "examples/rootfs/x86_windows", "windows")
```

The below Youtube video shows how the above example works.

[![qiling DEMO 1: hotpatching a windows crackme](http://img.youtube.com/vi/j_IYXxgXj7E/0.jpg)](https://www.youtube.com/watch?v=j_IYXxgXj7E "Video DEMO 1")


#### Wannacry demo

- The below Youtube video shows how Qiling analyzes Wannacry malware.

[![qiling DEMO 0: catching wannacry's killer swtich](http://img.youtube.com/vi/gVtpcXBxwE8/0.jpg)](https://www.youtube.com/watch?v=gVtpcXBxwE8 "Video DEMO 0")

---

#### Qltool

Qiling also provides a friendly tool named `qltool` to quickly emulate shellcode & executable binaries.

To emulate a binary, run:

```
$ ./qltool run -f examples/rootfs/arm_linux/bin/arm32-hello --rootfs examples/rootfs/arm_linux/

```

To run shellcode, run:

```
$ ./qltool shellcode --os linux --arch x86 --asm -f examples/shellcodes/lin32_execve.asm

```

---

#### Contact

Get the latest info from out webiste https://www.qiling.io.

You can contact us at email address info@qiling.io, or via Twitter [https://twitter.com/qiling_io](qiling_io).

---

#### Core developers

- kaijern (xwing)s Lau <kj@qiling.io>
- Nguyen Anh Quynh <aquynh@gmail.com>
- tianze (Dliv3) Ding <dddliv3@gmail.com>
- bowen (w1tcher) Sun <w1tcher.bupt@gmail.com>
- huitao (null) Chen <null@qiling.io>
