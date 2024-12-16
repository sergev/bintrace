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
    PRINT_FIELD("   a0", a0);
    PRINT_FIELD("   a1", a1);
    PRINT_FIELD("   a2", a2);
    PRINT_FIELD("   a3", a3);
    PRINT_FIELD("   a4", a4);
    PRINT_FIELD("   a5", a5);
    PRINT_FIELD("   a6", a6);
    PRINT_FIELD("   a7", a7);

    PRINT_FIELD("   t0", t0);
    PRINT_FIELD("   t1", t1);
    PRINT_FIELD("   t2", t2);
    PRINT_FIELD("   t3", t3);
    PRINT_FIELD("   t4", t4);
    PRINT_FIELD("   t5", t5);
    PRINT_FIELD("   t6", t6);

    PRINT_FIELD("   s0", s0);
    PRINT_FIELD("   s1", s1);
    PRINT_FIELD("   s2", s2);
    PRINT_FIELD("   s3", s3);
    PRINT_FIELD("   s4", s4);
    PRINT_FIELD("   s5", s5);
    PRINT_FIELD("   s6", s6);
    PRINT_FIELD("   s7", s7);
    PRINT_FIELD("   s8", s8);
    PRINT_FIELD("   s9", s9);
    PRINT_FIELD("   s10", s10);
    PRINT_FIELD("   s11", s11);

    PRINT_FIELD("   ra", ra);
    PRINT_FIELD("   sp", sp);
    PRINT_FIELD("   gp", gp);
    PRINT_FIELD("   tp", tp);
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
