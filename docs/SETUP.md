#### Detailed installation guide

For this installation guide, we use Ubuntu desktop 18.04.3 LTS 64 bit. You can grab a copy of official Ubuntu ISO images from [Ubuntu CD mirrors](https://launchpad.net/ubuntu/+cdmirrors). Update your Ubuntu system and install required software and libraries with command below:
```
sudo apt install python3-pip git cmake
```
This will install required python3, pip3, git tools and other essentials libraries to proceed with next step

Once completed, you can clone Qiling Framework source and run setup to install it.
```
git clone https://github.com/qilingframework/qiling
cd qiling && sudo pip3 install -r requirements.txt
sudo python3 setup.py install 
```

---

#### Important note on Windows DLLs

Due to distribution restriction, we do not bundle Microsoft Windows DLL files and registry. You need to copy respective DLLs and registry from Microsoft Windows System


Refer to [DLLX86.txt](DLLX86.txt) for Windows 32bit DLLs hashes and file version

Refer to [DLLX8664.txt](DLLX8664.txt) for Windows 64bit DLLs hashes and file version

Refer to [REGISTRY.md](REGISTRY.md) for Windows registry
