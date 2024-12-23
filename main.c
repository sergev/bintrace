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
#include <getopt.h>
#include "trace.h"

FILE *out;

// Handle for disassembler.
csh disasm;

static void usage()
{
    printf("Usage:\n");
    printf("    bintrace [-o file] [-a] command [argument ...]\n");
    printf("Options:\n");
    printf("    -o file     Write the trace to file instead of stderr\n");
    printf("    -a          Append to the specified file rather than overwriting it\n");
    exit(-1);
}

int main(int argc, char *argv[])
{
    bool aflag = false;
    char *ofn = NULL;
    int ch;

    while ((ch = getopt(argc, argv, "ao:")) != -1) {
        switch ((char)ch) {
        case 'a':
            aflag = true;
            break;
        case 'o':
            ofn = optarg;
            break;
        case '?':
        default:
            usage();
        }
    }
    argv += optind;
    argc -= optind;
    if (argc < 1) {
        usage();
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
#elif __mips__
    int status = cs_open(CS_ARCH_MIPS, CS_MODE_MIPS32, &disasm);
#elif __riscv
    int status = cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC, &disasm);
#else
#error "This architecture is not supported"
#endif
    if (status != CS_ERR_OK) {
        perror("cs_open");
        exit(-1);
    }

    out = stderr;
    if (ofn) {
        out = fopen(ofn, aflag ? "ae" : "we");
        if (out == NULL) {
            perror(ofn);
            exit(-1);
        }
        setvbuf(out, (char *)NULL, _IONBF, (size_t)0);
    }
    trace(argv);

    cs_close(&disasm);
}
