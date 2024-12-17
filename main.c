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
#include "trace.h"

// Handle for disassembler.
csh disasm;

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: bintrace ./file\n");
        exit(-1);
    }

    // Initialize disassembler.
#if __x86_64__
    int status = cs_open(CS_ARCH_X86, CS_MODE_64, &disasm);
#elif __i386__
    int status = cs_open(CS_ARCH_X86, CS_MODE_32, &disasm);
#elif __ARM_ARCH_ISA_ARM
    int status = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &disasm);
#elif __ARM_ARCH_ISA_A64
    int status = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &disasm);
#elif __riscv
    int status = cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64, &disasm);
#else
#   error "This architecture is not supported"
#endif
    if (status != CS_ERR_OK) {
        perror("cs_open");
        exit(-1);
    }

    trace(argv[1]);

    cs_close(&disasm);
}
