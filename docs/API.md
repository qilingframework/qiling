#### Pre-Loader settings
In pre-loader(during initialization) state, there are few options can be configured

required:
```
path
rootfs
```

required for shellcode execution only:
```
ostype
arch
```

additional options
```
stack_address = 0xhexaddress
stack_size = 0xhexaddress
interp_base = 0xhexaddress
mmap_start = 0xhexaddress
output = ["debug","off","disasm","dump"] // dump=(disam + debug)
consolelog
root = True || False // Enabled virtual root, add 8000 to open port below 1024
reg_dir = /dir/path/to/clean_registery // must within rootfs
reg_diff = /file/path/to/registry_dump // must within rootfs
debug_stop = True || False // stop and exit if there is debug related error  
```
#### Pre-Execution Settings
APIs allow users to instuments a executeable file/shellcode before executions
```
```


#### Qiling's Coding Style
Some tips if you with to sent your pull request to Qiling Framework
```
ql.nprint("")
```
ql.nprint will not print anything when output="off"


```
ql.dprint("")
```
ql.dprint will only print anything when output="dump" or output="debug"

### 
