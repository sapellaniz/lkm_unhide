# lkm_unhide

lkm_unhide is a LKM Rootkits Detection Tool for Linux Kernels 5.x/6.x.

It can find hidden LKM Rootkits scanning memory regions between unhidden modules.

### Usage

Verify if the kernel is 5.x/6.x
```
uname -r
```

Clone the repository
```
git clone https://github.com/sapellaniz/lkm_unhide
```

Enter the folder
```
cd lkm_unhide
```

Compile
```
make
```

Load the module(as root)
```
insmod lkm_unhide.ko
```

Unload the module(as root)
```
rmmod lkm_unhide.ko
```

Check if it has detected any hidden module
```
dmesg | grep lkm_unhide
```

Unload any hidden module
```
rmmod <hidden_module_name>
```
