#### Detailed installation guide

For this installation guide, we use Ubuntu desktop 18.04.3 LTS 64 bit. You can grab a copy of official Ubuntu ISO images from [Ubuntu CD mirrors](https://launchpad.net/ubuntu/+cdmirrors). Update the system and install pip3, git and cmake
```
sudo apt-get update
sudo apt-get upgrade
sudo apt install python3-pip git cmake
```

Once completed, clone a copy of Qiling Framework source from github and run setup to install it.
```
git clone https://github.com/qilingframework/qiling
cd qiling
sudo python3 setup.py install 
```

---

#### Important note on Windows DLLs and registry

Due to distribution restriction, Qiling Framework will not bundle Microsoft Windows DLL files and registry. Please copy respective DLLs and registry from Microsoft Windows System, usually found in C:\Windows\system32 and place them in $rootfs/dlls


Refer to [DLLX86.txt](https://github.com/qilingframework/qiling/blob/master/docs/DLLX86.txt) for Windows 32bit DLLs hashes and file version

Refer to [DLLX8664.txt](https://github.com/qilingframework/qiling/blob/master/docs/DLLX8664.txt) for Windows 64bit DLLs hashes and file version

To export Windows Registry from Windows
```
ntuser hive : C:\Users\Default\NTUSER.DAT 
reg save hklm\system SYSTEM
reg save hklm\security SECURITY
reg save hklm\software SOFTWARE
reg save hklm\SAM SAM
```

---

#### Installation notes on macOS >= 10.14

Keystone-engine compilation from py-pip fails (on Mojave at least) because i386 architecture is deprecated for macOS. 

```
CMake Error at /usr/local/Cellar/cmake/3.15.4/share/cmake/Modules/CMakeTestCCompiler.cmake:60 (message):
  The C compiler

    "/Library/Developer/CommandLineTools/usr/bin/cc"

  is not able to compile a simple test program.

  It fails with the following output:
```

A temporary workaround is to install keystone-engine from source:
* Remove `keystone-engine>=0.9.1.post3` line from `requirements.txt`
* Install keystone-engine Python binding from source:
```
git clone https://github.com/keystone-engine/keystone
cd keystone
mkdir build
cd build
../make-share.sh
cd ../bindings/python
sudo make install
```

Once completed workaround installation, run Qiling Framework setup.
