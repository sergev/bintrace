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
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <elf.h>
#include <asm/ptrace.h>

#include "trace.h"

//
// Print current CPU instruction.
//
static void print_riscv64_instruction(int child, unsigned long long address)
{
    // Read opcode from child process.
    // Max instruction size for riscv architecture is 4 bytes.
    uint64_t code[1];
    code[0] = ptrace(PTRACE_PEEKTEXT, child, (void*)address, NULL);

    // Disassemble one instruction.
    cs_insn *insn = NULL;
    size_t count = cs_disasm(disasm, (uint8_t*)code, sizeof(code), address, 1, &insn);
    printf("0x%016llx: ", address);
    if (count == 0) {
        printf("(unknown)\n");
    } else {
        switch (insn[0].size) {
        case 4:
            printf(" %04x", (uint32_t)code[0]);
            break;
        case 2:
            printf(" %02x    ", (uint16_t)code[0]);
            break;
        default:
            fprintf(stderr, "Unexpected instruction size: %u bytes\n", insn[0].size);
            exit(-1);
        }
        printf("   %s %s\n", insn[0].mnemonic, insn[0].op_str);
        cs_free(insn, count);
    }
}

//
// Get CPU state.
// Print program counter, disassembled instruction and changed registers.
//
static void print_riscv64_registers(const struct user_regs_struct *cur)
{
    static struct user_regs_struct prev;

#define PRINT_FIELD(name, field) \
    if (cur->field != prev.field) { \
        printf("    " name " = %#lx\n", cur->field); \
    }

    PRINT_FIELD("   x1", ra);
    PRINT_FIELD("   x2", sp);
    PRINT_FIELD("   x3", gp);
    PRINT_FIELD("   x4", tp);

    PRINT_FIELD("   x5", t0);
    PRINT_FIELD("   x6", t1);
    PRINT_FIELD("   x7", t2);

    PRINT_FIELD("   x8", s0); // fp
    PRINT_FIELD("   x9", s1);

    PRINT_FIELD("  x10", a0);
    PRINT_FIELD("  x11", a1);
    PRINT_FIELD("  x12", a2);
    PRINT_FIELD("  x13", a3);
    PRINT_FIELD("  x14", a4);
    PRINT_FIELD("  x15", a5);
    PRINT_FIELD("  x16", a6);
    PRINT_FIELD("  x17", a7);

    PRINT_FIELD("  x18", s2);
    PRINT_FIELD("  x19", s3);
    PRINT_FIELD("  x20", s4);
    PRINT_FIELD("  x21", s5);
    PRINT_FIELD("  x22", s6);
    PRINT_FIELD("  x23", s7);
    PRINT_FIELD("  x24", s8);
    PRINT_FIELD("  x25", s9);
    PRINT_FIELD("  x26", s10);
    PRINT_FIELD("  x27", s11);

    PRINT_FIELD("  x28", t3);
    PRINT_FIELD("  x29", t4);
    PRINT_FIELD("  x30", t5);
    PRINT_FIELD("  x31", t6);
#undef PRINT_FIELD

    prev = *cur;
}

//
// Get CPU state.
// Print program counter, disassembled instruction and changed registers.
//
void print_cpu_state(int child)
{
    struct user_regs_struct regs;
    struct iovec iov = { &regs, sizeof(regs) };

    errno = 0;
    if (ptrace(PTRACE_GETREGSET, child, (void*)NT_PRSTATUS, &iov) < 0) {
        perror("PTRACE_GETREGSET");
        exit(-1);
    }
    print_riscv64_registers(&regs);
#if 0
    //TODO: print FP registers
    struct user_fpregs_struct fpregs;
    errno = 0;
    if (ptrace(PTRACE_GETFPREGS, child, NULL, &fpregs) < 0) {
        perror("PTRACE_GETFPREGS");
        exit(-1);
    }
    print_fpregs(&fpregs);
#endif
    print_riscv64_instruction(child, regs.pc);
}
