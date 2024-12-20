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
#include <sys/user.h>

#include "trace.h"

//
// Print current CPU instruction.
//
static void print_amd64_instruction(int child, unsigned long long address)
{
    // Read opcode from child process.
    // Max instruction size for x86-64 architecture is 16 bytes.
    uint64_t code[2];
    errno = 0;
    code[0] = ptrace(PT_READ_I, child, (void*)address, 0);
    code[1] = ptrace(PT_READ_I, child, (void*)(address + 8), 0);
    if (errno) {
        perror("PT_READ_I");
        exit(-1);
    }

    // Disassemble one instruction.
    cs_insn *insn = NULL;
    size_t count = cs_disasm(disasm, (uint8_t*)code, sizeof(code), address, 1, &insn);
    fprintf(out, "0x%016llx: ", address);
    if (count == 0) {
        fprintf(out, "(unknown)\n");
    } else {
        unsigned n;
        for (n = 0; n < insn[0].size; n++) {
            fprintf(out, " %02x", insn[0].bytes[n]);
        }
        while (n++ < 7) {
            fprintf(out, "   ");
        }
        fprintf(out, "   %s %s\n", insn[0].mnemonic, insn[0].op_str);
        cs_free(insn, count);
    }
}

//
// Get CPU state.
// Print program counter, disassembled instruction and changed registers.
//
static void print_amd64_registers(const struct reg *cur)
{
    static struct reg prev;

#define PRINT_FIELD(name, field) \
    if (cur->field != prev.field) { \
        fprintf(out, "    " name " = %#lx\n", cur->field); \
    }
#define PRINT_FLD32(name, field) \
    if (cur->field != prev.field) { \
        fprintf(out, "    " name " = %#x\n", cur->field); \
    }

    PRINT_FIELD("   rax", r_rax);
    PRINT_FIELD("   rbx", r_rbx);
    PRINT_FIELD("   rcx", r_rcx);
    PRINT_FIELD("   rdx", r_rdx);
    PRINT_FIELD("   rsi", r_rsi);
    PRINT_FIELD("   rdi", r_rdi);
    PRINT_FIELD("   rbp", r_rbp);
    PRINT_FIELD("   rsp", r_rsp);

    PRINT_FIELD("    r8", r_r8);
    PRINT_FIELD("    r9", r_r9);
    PRINT_FIELD("   r10", r_r10);
    PRINT_FIELD("   r11", r_r11);
    PRINT_FIELD("   r12", r_r12);
    PRINT_FIELD("   r13", r_r13);
    PRINT_FIELD("   r14", r_r14);
    PRINT_FIELD("   r15", r_r15);

    PRINT_FIELD("    ss", r_ss);
    PRINT_FIELD("    cs", r_cs);
    PRINT_FLD32("    ds", r_ds);
    PRINT_FLD32("    es", r_es);
    PRINT_FLD32("    fs", r_fs);
    PRINT_FLD32("    gs", r_gs);

    PRINT_FIELD("eflags", r_rflags);
    // Unused: r_trapno
    // Unused: r_err

#undef PRINT_FIELD
#undef PRINT_FLD32

    prev = *cur;
}

//
// Get CPU state.
// Print program counter, disassembled instruction and changed registers.
//
void print_cpu_state(int child)
{
    struct reg regs;

    errno = 0;
    if (ptrace(PT_GETREGS, child, (caddr_t)&regs, NT_PRSTATUS) < 0) {
        perror("PT_GETREGS");
        exit(-1);
    }
    print_amd64_registers(&regs);
#if 0
    //TODO: print FP registers
    struct fpregs fpregs;
    errno = 0;
    if (ptrace(PT_GETFPREGS, child, &fpregs, 0) < 0) {
        perror("PT_GETFPREGS");
        exit(-1);
    }
    print_fpregs(&fpregs);
#endif
    print_amd64_instruction(child, regs.r_rip);
}
