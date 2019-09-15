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
- True framework in Python, making it easy to build customized security analysis tools on top

Qiling is backed by [Unicorn engine](http://www.unicorn-engine.org).

Visit our website https://www.qiling.io for more information.

---

#### Announcement

We are currently in Alpha test phase, that will be followed by public beta release.

This is a call for testers: please email your short instroduction, with github/gitlab ID to info@qiling.io for shortlisting.

Evaluation will be based on your open source participation.

---

#### License

This project is released and distributed under [free software license GPLv2](COPYING).

---

#### Qiling vs other Emulators

There are many open source emulators, but two projects closest to Qiling are [Unicorn](http://www.unicorn-engine.org) & [Qemu usermode](https://qemu.org). This section explains the main differences of Qiling against them.

##### Qiling vs Unicorn engine

Built on top of Unicorn, but Qiling & Unicorn are two different animals.

- Unicorn is just a CPU emulator, so it focuses on emulating CPU instructions, that can understand emulator memory. Beyond that, Unicorn is not aware of higher level concepts, such as dynamic libraries, system calls, I/O handling or executable formats like PE, MachO or ELF. As a result, Unicorn can only emulate raw machine instructions, without Operating System (OS) context.
- Qiling is designed as a higher level framework, that leverages Unicorn to emulate CPU instructions, but can understand OS: it has executable format loaders (for PE, MachO & ELF at the moment), dynamic linkers (so we can load & relocate shared libraries), syscall & IO handlers. For this reason, Qiling can run excutable binaries that normally runs in native OS.

##### Qiling vs Qemu usermode

Qemu usermode does similar thing to our emulator, that is to emulate whole executable binaries in cross-architecture way. However, Qiling offers some important differences against Qemu usermode.

- Qiling is a true analysis framework, that allows you to build your own dynamic analysis tools on top (in friendly Python language). Meanwhile, Qemu is just a tool, not a framework.
- Qiling can perform dynamic instrumentation, and can even hotpatch code at runtime. Qemu does not do either.
- Not only working cross-architecture, Qiling is also cross-platform, so for example you can run Linux ELF file on top of Windows. In contrast, Qemu usermode only run binary of the same OS, such as Linux on Linux, due to the way it forwards syscall from emulated code to native OS.
- Qiling supports more platforms, including Windows, MacOS, Linux & BSD. Qemu usermode can only handles Linux & BSD.

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
from qiling import *

def force_call_dialog_func(ql):
    # get DialogFunc address
    lpDialogFunc = ql.unpack32(ql.mem_read(ql.sp - 0x8, 4))
    # setup stack memory for DialogFunc
    ql.stack_push(0)
    ql.stack_push(1001)
    ql.stack_push(273)
    ql.stack_push(0)
    ql.stack_push(0x0401018)
    # force EIP to DialogFunc
    ql.pc = lpDialogFunc


def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs)
    # NOP out some code
    ql.patch(0x004010B5, b'\x90\x90')
    ql.patch(0x004010CD, b'\x90\x90')
    ql.patch(0x0040110B, b'\x90\x90')
    ql.patch(0x00401112, b'\x90\x90')
    # hook at an address with a callback
    ql.hook_address(0x00401016, force_call_dialog_func)
    ql.run()


if __name__ == "__main__":
    my_sandbox(["rootfs/x86_windows/bin/Easy_CrackMe.exe"], "rootfs/x86_windows")
```

The below Youtube video shows how the above example works.

[![qiling DEMO 1: hotpatching a windows crackme](http://img.youtube.com/vi/p17ONUbCnUU/0.jpg)](https://www.youtube.com/watch?v=p17ONUbCnUU "Video DEMO 1")


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

Get the latest info from out webiste https://www.qiling.io

Contact us at email info@qiling.io, or via Twitter [@qiling_io](https://twitter.com/qiling_io)

任何疑问请联系[麒麟框架官方微博](https://www.weibo.com/sgniwx)

---

#### Core developers

- LAU kaijern (xwings) <kj@qiling.io>
- NGUYEN Anh Quynh <aquynh@gmail.com>
- DING tianZe (D1iv3) <dddliv3@gmail.com>
- SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
- CHEN huitao (null) <null@qiling.io>
- YU tong (sp1ke) <spikeinhouse@gmail.com>

