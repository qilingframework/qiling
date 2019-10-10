#### Detailed installation guide

For this installation guide, we use Ubuntu desktop 18.04.3 LTS 64 bit. You can grab a copy of official Ubuntu ISO images from [Ubuntu CD mirrors](https://launchpad.net/ubuntu/+cdmirrors). Update your Ubuntu system and install required software and libraries with command below:

```
sudo apt install python3-pip python make cmake build-essential gcc git
```

This will install required python2, python3, pip3, cmake, git tools, compiler and other essentials libraries to proceed with next step

Once completed installation of dependencies, you can proceed to installation for [Capstone](https://github.com/aquynh/capstone/blob/master/COMPILE.TXT) and [Keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)

```
sudo pip3 install wheel capstone keystone-engine python-registry pefile>=2019.4.18
```

You can simply run commands below for installation via source, by cloning unicorn-engine source with git. For more information on Unicorn-Engine installation, please refer to [Unicorn Installation Instructions](https://github.com/unicorn-engine/unicorn/blob/master/docs/COMPILE-NIX.md) for more details

```
git clone https://github.com/unicorn-engine/unicorn
cd unicorn && ./make.sh && sudo ./make.sh install

```

To install the Unicorn-engine python binding

```
sudo pip3 install --pre unicorn
```

Finally, clone Qiling Framework source and run setup to install it.

```
git clone https://github.com/qilingframework/qiling
cd qiling && sudo python3 setup.py install 
```

---

#### Important note on Windows DLLs

Due to distribution restriction, we do not bundle Microsoft Windows DLL files. You need to copy respective DLLs from Microsoft Windows System

Refer to [DLLX86.txt](DLLX86.txt) for Windows 32bit DLLs hashes and file version

Refer to [DLLX8664.txt](DLLX8664.txt) for Windows 64bit DLLs hashes and file version
