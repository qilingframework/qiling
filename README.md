[![Gitter](https://badges.gitter.im/qilingframework/community.svg)](https://gitter.im/qilingframework/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
[![Build Status](https://travis-ci.com/qilingframework/qiling.svg?branch=dev)](https://travis-ci.com/qilingframework/qiling)
![Docker Image CI](https://github.com/qilingframework/qiling/workflows/Docker%20Image%20CI/badge.svg?branch=dev)
---

<p align="center">
<img width="150" height="150" src="https://raw.githubusercontent.com/qilingframework/qiling/master/docs/qiling_small.png">
</p>

Qiling is an advanced binary emulation framework, with the following features:

- Cross platform: Windows, MacOS, Linux, BSD, UEFI, DOS
- Cross architecture: X86, X86_64, Arm, Arm64, MIPS, 8086
- Multiple file formats: PE, MachO, ELF, COM
- Emulate & sandbox machine code in a isolated environment
- Supports cross architecture and platform debugging capabilities
- Provide high level API to setup & configure the sandbox
- Fine-grain instrumentation: allow hooks at various levels (instruction/basic-block/memory-access/exception/syscall/IO/etc)
- Allow dynamic hotpatch on-the-fly running code, including the loaded library
- True framework in Python, making it easy to build customized security analysis tools on top

Qiling is backed by [Unicorn engine](http://www.unicorn-engine.org).

Visit our website https://www.qiling.io for more information.

---

#### License

This project is released and distributed under [free software license GPLv2](https://github.com/qilingframework/qiling/blob/master/COPYING).

---

#### Qiling vs other Emulators

There are many open source emulators, but two projects closest to Qiling are [Unicorn](http://www.unicorn-engine.org) & [Qemu usermode](https://qemu.org). This section explains the main differences of Qiling against them.

##### Qiling vs Unicorn engine

Built on top of Unicorn, but Qiling & Unicorn are two different animals.

- Unicorn is just a CPU emulator, so it focuses on emulating CPU instructions, that can understand emulator memory. Beyond that, Unicorn is not aware of higher level concepts, such as dynamic libraries, system calls, I/O handling or executable formats like PE, MachO or ELF. As a result, Unicorn can only emulate raw machine instructions, without Operating System (OS) context.
- Qiling is designed as a higher level framework, that leverages Unicorn to emulate CPU instructions, but can understand OS: it has executable format loaders (for PE, MachO & ELF at the moment), dynamic linkers (so we can load & relocate shared libraries), syscall & IO handlers. For this reason, Qiling can run executable binary without requiring its native OS.

##### Qiling vs Qemu usermode

Qemu usermode does similar thing to our emulator, that is to emulate whole executable binaries in cross-architecture way. However, Qiling offers some important differences against Qemu usermode.

- Qiling is a true analysis framework, that allows you to build your own dynamic analysis tools on top (in friendly Python language). Meanwhile, Qemu is just a tool, not a framework.
- Qiling can perform dynamic instrumentation, and can even hotpatch code at runtime. Qemu does not do either.
- Not only working cross-architecture, Qiling is also cross-platform, so for example you can run Linux ELF file on top of Windows. In contrast, Qemu usermode only run binary of the same OS, such as Linux ELF on Linux, due to the way it forwards syscall from emulated code to native OS.
- Qiling supports more platforms, including Windows, MacOS, Linux & BSD. Qemu usermode can only handle Linux & BSD.

---

#### Installation
Please see [setup guide](https://docs.qiling.io/en/latest/install/) file for how to install Qiling Framework.

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
    my_sandbox(["examples/rootfs/x86_windows/bin/x86_hello.exe"], "examples/rootfs/x86_windows")
```

- Below example shows how to use Qiling framework to dynamically patch a Windows crackme, make it always display "Congratulation" dialog.

```python
from qiling import *

def force_call_dialog_func(ql):
    # get DialogFunc address
    lpDialogFunc = ql.unpack32(ql.mem.read(ql.reg.esp - 0x8, 4))
    # setup stack memory for DialogFunc
    ql.stack_push(0)
    ql.stack_push(1001)
    ql.stack_push(273)
    ql.stack_push(0)
    ql.stack_push(0x0401018)
    # force EIP to DialogFunc
    ql.reg.eip = lpDialogFunc


def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs)
    # NOP out some code
    ql.patch(0x004010B5, b'\x90\x90')
    ql.patch(0x004010CD, b'\x90\x90')
    ql.patch(0x0040110B, b'\x90\x90')
    ql.patch(0x00401112, b'\x90\x90')
    # hook at an address with a callback
    ql.hook_address(force_call_dialog_func, 0x00401016)
    ql.run()


if __name__ == "__main__":
    my_sandbox(["rootfs/x86_windows/bin/Easy_CrackMe.exe"], "rootfs/x86_windows")
```

The below Youtube video shows how the above example works.

#### GDBserver with IDAPro demo

- Solving a simple CTF challenge with Qiling Framework and IDAPro

[![Solving a simple CTF challenge with Qiling Framework and IDAPro](https://i.ytimg.com/vi/SPjVAt2FkKA/0.jpg)](https://www.youtube.com/watch?v=SPjVAt2FkKA "Video DEMO 2")

#### Fuzzing with Qiling Unicornalf

- More information on fuzzing with Qiling Unicornalf can be found [here](https://github.com/qilingframework/qiling/blob/dev/examples/fuzz_example_x64/README.md).

[![qiling DEMO 2: Fuzzing with Qiling Unicornalf](https://raw.githubusercontent.com/qilingframework/qilingframework.github.io/master/images/qilingfzz-s.png)](https://raw.githubusercontent.com/qilingframework/qiling/dev/examples/fuzzing/qilingfzz.png "Demo #2 Fuzzing with Qiling Unicornalf")

#### Emulating ARM router firmware on Ubuntu X64 machine

- Qiling Framework hot-patch and emulates ARM router's /usr/bin/httpd on a X86_64Bit Ubuntu

[![qiling DEMO 3: Fully emulating httpd from ARM router firmware with Qiling on Ubuntu X64 machine](https://raw.githubusercontent.com/qilingframework/qilingframework.github.io/master/images/demo3-en.jpg)](https://www.youtube.com/watch?v=Nxu742-SNvw "Demo #3 Emulating ARM router firmware on Ubuntu X64 machine")

#### Emulating UEFI

- Qiling Framework emulates UEFI

[![qiling DEMO 4: Emulating UEFI](https://raw.githubusercontent.com/qilingframework/qilingframework.github.io/master/images/demo4-s.png)](https://raw.githubusercontent.com/qilingframework/qilingframework.github.io/master/images/demo4-en.png "Demo #4 Emulating UEFI")

---

#### Qltool

Qiling also provides a friendly tool named `qltool` to quickly emulate shellcode & executable binaries.

With qltool, easy execution can be performed:


With shellcode:

```
$ ./qltool shellcode --os linux --arch arm --hex -f examples/shellcodes/linarm32_tcp_reverse_shell.hex
```

With binary file:

```
$ ./qltool run -f examples/rootfs/x8664_linux/bin/x8664_hello --rootfs  examples/rootfs/x8664_linux/
```

With binary and GDB debugger enable:

```
$ ./qltool run -f examples/rootfs/x8664_linux/bin/x8664_hello --gdb 127.0.0.1:9999 --rootfs examples/rootfs/x8664_linux
```

See  https://docs.qiling.io/  for more details

With code coverage collection (UEFI only for now):

```
$ ./qltool run -f examples/rootfs/x8664_efi/bin/TcgPlatformSetupPolicy --rootfs examples/rootfs/x8664_efi --coverage-format drcov --coverage-file TcgPlatformSetupPolicy.cov
```
---

#### Remote Debugger

Qiling supports **remote debugging** now.

See  https://docs.qiling.io/  for more details

---

#### Contact

Get the latest info from our website https://www.qiling.io

Contact us at email info@qiling.io, or via Twitter [@qiling_io](https://twitter.com/qiling_io) or [Weibo](https://www.weibo.com/sgniwx)

---

#### Core developers

- LAU kaijern (xwings) <kj@qiling.io>
- NGUYEN Anh Quynh <aquynh@gmail.com>
- DING tianZe (D1iv3) <dddliv3@gmail.com>
- SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
- CHEN huitao (null) <null@qiling.io>
- YU tong (sp1ke) <spikeinhouse@gmail.com>
- Earl Marcus (klks84) klks84@gmail.com 

#### Travis-CI, Docker, Website and Documentation

- FOO Kevin (chfl4gs) <chbsd64@qiling.io>

#### Key Contributors (in no particular order)

- lazymio
- kabeor
- 0ssigeno
- liba2k
- assafcarlsbad
- ucgJhe
- jhumble
