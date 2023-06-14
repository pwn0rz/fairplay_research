# Poor Man's Kernel Debuger

This project loads `FairplayIOKit` kernel driver into userspace and make it possible for LLDB to debug

# How to Compile

In project folder
```shell
mkdir build && cd build
cmake ..
make
```

# Procedure
1. FairplayIOKit send mig request to fairplayd at `uf_setup_from_fp`
2. fairplayd talks to FairplayIOKit method `ucRunversiond`, hw aes involved
3. FairplayIOKit received mig response and do decryption, no hw aes

# Notice

It has a built-in branch tracing support, before debugging in lldb, you might have to disable this feaure by comment the relevant code


# How to Debug

**Caveats**

Apple Silicon Device required, tested on `11.2_20D64`, may not work on `11.3` and newer version.

Root privileges required for `host_get_special_port`.

Before debugging, you need to make a breakpoint, right after we notify debugger of the mannually loaded KEXT. `fairplay_init` can be a good breakpoint.

```
lldb build/uloader 
(lldb) b fairplay_init
Breakpoint 1: where = uloader`fairplay_init, address = 0x0000000100007bb8
(lldb) r
Process 30277 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
    frame #0: 0x0000000100007bb8 uloader`fairplay_init
uloader`fairplay_init:
->  0x100007bb8 <+0>:  sub    sp, sp, #0x50             ; =0x50 
    0x100007bbc <+4>:  stp    x29, x30, [sp, #0x40]
    0x100007bc0 <+8>:  add    x29, sp, #0x40            ; =0x40 
    0x100007bc4 <+12>: stur   x0, [x29, #-0x10]
Target 0: (uloader) stopped.
```

List images like a kernel debugger
```
(lldb) image list
[  0] 2EB7F208-4321-3545-A778-FE25D1FEB253 0x0000000100000000 /Users/pwn0rz/work/dev/fairplay/build/uloader 
[ 44] A9299904-1979-3514-A8DB-9EDA8159DD55 0x000000010045c000 /System/Library/Extensions/FairPlayIOKit.kext/Contents/MacOS/FairPlayIOKit 
```

Set-up a breakpoint. Even watchpoint is possible `:3`
```
(lldb) b fcHfFIGhsx
Breakpoint 2: where = FairPlayIOKit`fcHfFIGhsx, address = 0x000000010056bbe8
```

# Additional Resources
- Have a look at `tools` folder
- CVE-2021-1791: https://gist.github.com/pwn0rz/e34ab9f6e46956621a9d4f98cf222320
