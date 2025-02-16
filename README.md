Understanding the fundamental operations of a computer involves
observing the execution of machine code instructions and the
corresponding modifications to processor registers. Unfortunately,
traditional debugging tools are not designed to provide this level of
visibility. To bridge this gap and empower users to explore computer
architecture in greater detail, I have developed a novel tool.

Utility `bintrace` runs a given native binary, displaying each executed
CPU instruction and corresponding register modifications.
It uses `ptrace()` system call. For now it can run only on Linux.
The following architectures are supported:

 * x86_64 aka amd64
 * i386
 * arm64 aka aarch64
 * arm32 (limited features)
 * powerpc32

Unfortunately, Linux kernel does not support single-stepping on arm32
and riscv64 processors. So only syscalls can be traced.

# Pre-requisites

For Ubuntu:
```
    sudo apt install libcapstone-dev
```
For MacOS:
```
    brew install capstone
```
For FreeBSD:
```
    doas pkg install capstone
```

# Build

To build the `bintrace` utility and demo files, use:
```
    make
```

# Arguments and options
```
Usage:
    bintrace [-o file] [-a] command [argument ...]
Options:
    -o file     Write the trace to file instead of stderr
    -a          Append to the specified file rather than overwriting it
```

# Demo

Run shell script `demo.sh` to see how it works. For example:
```
$ ./demo.sh
Starting program: ./hello-amd64-linux
       rsp = 0x7ffe2f92a700
        cs = 0x33
        ss = 0x2b
    eflags = 0x200
0x0000000000401000:  48 c7 c0 01 00 00 00   mov rax, 1
       rax = 0x1
    eflags = 0x202
0x0000000000401007:  48 c7 c7 01 00 00 00   mov rdi, 1
       rdi = 0x1
0x000000000040100e:  48 8d 35 15 00 00 00   lea rsi, [rip + 0x15]
       rsi = 0x40102a
0x0000000000401015:  48 c7 c2 0d 00 00 00   mov rdx, 0xd
       rdx = 0xd
0x000000000040101c:  0f 05                  syscall
Hello world!
       rax = 0xd
       rcx = 0x40101e
       r11 = 0x302
0x000000000040101e:  48 c7 c0 3c 00 00 00   mov rax, 0x3c
       rax = 0x3c
0x0000000000401025:  48 31 ff               xor rdi, rdi
       rdi = 0
    eflags = 0x246
0x0000000000401028:  0f 05                  syscall
Process exited normally.
```

# OSes and CPU architectures

Support of single-stepping per operating system and machine architecture:

Architecture | Linux | FreeBSD | MacOS
-------------|-------|---------|------
amd64/x86-64 | yes   | yes     | yes
i386         | yes   | yes     | -
arm64        | yes   | yes     | yes
arm32        | -     | yes     | -
mips64       | -     | yes     | -
mips32       | -     | -       | -
powerpc64    | yes   | yes     | yes
powerpc32    | yes   | yes     | yes
riscv64      | -     | -       | -
