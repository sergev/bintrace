//
// Output "Hello world!" to standard output.
// For Intel i386 architecture with GNU assembler, using Linux syscalls.
//
// Assemble with :
// cpp hello.S | as -o hello.o -
// ld -o hello hello.o
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
	mov     $ SYS_write, %eax   // syscall write(fd, message, size)
	mov     $1, %ebx            // fd - stdout
	lea     message, %ecx       // pointer to message
	mov     $13, %edx           // size
	int     $0x80               // do syscall

	mov     $ SYS_exit, %eax    // syscall exit(status)
	xor     %ebx, %ebx          // status - 0
	int     $0x80               // do syscall

message:
	.ascii  "Hello world!\n"
