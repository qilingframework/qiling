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
log_console
reg_dir = /dir/path/to/clean_registery // must within rootfs
reg_diff = /file/path/to/registry_dump // must within rootfs
```
#### Pre-Execution Settings
APIs allow users to instuments a executeable file/shellcode before executions
```
ql.set_callback
ql.patch
ql.root
ql.debug
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
