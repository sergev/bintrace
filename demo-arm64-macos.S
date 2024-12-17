//
// Output "Hello world!" to standard output.
// For ARM64 architecture with GNU assembler, using MacOS syscalls.
//
// Assemble with:
// cpp hello.S | as -o hello.o -
// ld hello.o -o hello
//
// Copyright (c) 2024 Serge Vakulenko
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
#include <sys/syscall.h>

        .text
        .align  2
        .globl  _main
_main:
        mov     x16, #SYS_write                 // syscall write(fd, message, size)
        mov     x0, #1                          // file descriptor 1 - stdout
        adrp    x1, message@PAGE                // high 20 bits of message address
        add     x1, x1, :lo12:message@PAGEOFF   // low 12 bits of message address
        mov     x2, 13                          // size
        svc     0x80                            // do system call

        mov     x16, #SYS_exit                  // syscall exit(status)
        mov     x0, #0                          // status - 0
        svc     0x80                            // do system call

message:
        .ascii  "Hello world!\n"
