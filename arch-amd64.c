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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <capstone/capstone.h>

#include "trace.h"

//
// Print current CPU instruction.
//
static void print_amd64_instruction(int child, unsigned long long address)
{
    // Read opcode from child process.
    // Max instruction size for x86-64 architecture is 16 bytes.
    uint64_t code[2];
    code[0] = ptrace(PTRACE_PEEKTEXT, child, (void*)address, NULL);
    code[1] = ptrace(PTRACE_PEEKTEXT, child, (void*)(address + 8), NULL);

    // Disassemble one instruction.
    cs_insn *insn = NULL;
    size_t count = cs_disasm(disasm, (uint8_t*)code, sizeof(code), address, 1, &insn);
    printf("0x%016llx: ", address);
    if (count == 0) {
        printf("(unknown)\n");
    } else {
        unsigned n;
        for (n = 0; n < insn[0].size; n++) {
            printf(" %02x", insn[0].bytes[n]);
        }
        while (n++ < 7) {
            printf("   ");
        }
        printf("   %s %s\n", insn[0].mnemonic, insn[0].op_str);
        cs_free(insn, count);
    }
    fflush(stdout);
}

//
// Get CPU state.
// Print program counter, disassembled instruction and changed registers.
//
static void print_amd64_registers(const struct user_regs_struct *cur)
{
    static struct user_regs_struct prev;

#define PRINT_FIELD(name, field) \
    if (cur->field != prev.field) { \
        printf("    " name " = %#llx\n", cur->field); \
    }
    PRINT_FIELD("   rax", rax);
    // Unused: orig_rax
    PRINT_FIELD("   rbx", rbx);
    PRINT_FIELD("   rcx", rcx);
    PRINT_FIELD("   rdx", rdx);
    PRINT_FIELD("   rbp", rbp);
    PRINT_FIELD("   rsi", rsi);
    PRINT_FIELD("   rdi", rdi);
    PRINT_FIELD("   rsp", rsp);

    PRINT_FIELD("    r8", r8 );
    PRINT_FIELD("    r9", r9 );
    PRINT_FIELD("   r10", r10);
    PRINT_FIELD("   r11", r11);
    PRINT_FIELD("   r12", r12);
    PRINT_FIELD("   r13", r13);
    PRINT_FIELD("   r14", r14);
    PRINT_FIELD("   r15", r15);

    PRINT_FIELD("    cs", cs);
    PRINT_FIELD("    ss", ss);
    PRINT_FIELD("    ds", ds);
    PRINT_FIELD("    es", es);
    PRINT_FIELD("    fs", fs);
    PRINT_FIELD("    gs", gs);
    // Unused: fs_base
    // Unused: gs_base

    PRINT_FIELD("eflags", eflags);
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
    struct user_fpregs_struct fpregs;

    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0) {
        perror("PTRACE_GETREGS");
        exit(-1);
    }
    print_amd64_registers(&regs);
#if 0
    //TODO: print FP registers
    if (ptrace(PTRACE_GETFPREGS, child, NULL, &fpregs) < 0) {
        perror("PTRACE_GETFPREGS");
        exit(-1);
    }
    print_fpregs(&fpregs);
#endif
    print_amd64_instruction(child, regs.rip);
}
