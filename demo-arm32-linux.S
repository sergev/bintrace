//
// Output "Hello world!" to standard output.
// For ARM32 architecture with GNU assembler, using Linux EABI syscalls.
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
        .globl  _start
_start:
	mov     r7, #SYS_write          // syscall write(fd, message, size)
	mov     r0, #1                  // file descriptor 1 - stdout
	movw    r1, #:lower16:message   // low 16-bits of message address
	movt    r1, #:upper16:message   // high 16-bits of message address
	mov     r2, #13                 // size
	svc     #0                      // do system call

	mov     r7, #SYS_exit           // syscall exit(status)
	mov     r0, #0                  // status - 0
	svc     #0                      // do system call

message:
        .ascii  "Hello world!\n"
