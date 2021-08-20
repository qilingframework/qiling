# EVM Fuzz Usage

python >= 3.8

## Installation

Install Qiling
```bash
git clone https://github.com/qilingframework/qiling_evm.git
cd qiling_evm
python3 -m pip install -e .
```

Install AFL
```bash
wget https://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
or
download from https://lcamtuf.coredump.cx/afl/

tar -zxvf afl-latest.tgz
cd afl.2.5.2b
make
sudo make install
```

Install AFL python binding
```
pip install python-afl
```

## Run Fuzz
```bash
cd qiling/examples/fuzzing/evm
./fuzz.sh
```

# TODO
- qiling/engine/evm/logic/system.py
    - create
    - create2 
- qiling/engine/evm/logic/call.py
    - call