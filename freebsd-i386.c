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
static void print_i386_instruction(int child, unsigned long address)
{
    // Read opcode from child process.
    // Max instruction size for i386 architecture is 16 bytes.
    uint32_t code[4];
    errno = 0;
    code[0] = ptrace(PT_READ_I, child, (void*)address, 0);
    code[1] = ptrace(PT_READ_I, child, (void*)(address + 4), 0);
    code[2] = ptrace(PT_READ_I, child, (void*)(address + 8), 0);
    code[3] = ptrace(PT_READ_I, child, (void*)(address + 12), 0);
    if (errno) {
        perror("PT_READ_I");
        exit(-1);
    }

    // Disassemble one instruction.
    cs_insn *insn = NULL;
    size_t count = cs_disasm(disasm, (uint8_t*)code, sizeof(code), address, 1, &insn);
    fprintf(out, "0x%08lx: ", address);
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
static void print_i386_registers(const struct reg *cur)
{
    static struct reg prev;

#define PRINT_FIELD(name, field) \
    if (cur->field != prev.field) { \
        fprintf(out, "    " name " = %#x\n", cur->field); \
    }

    PRINT_FIELD("   eax", r_eax);
    PRINT_FIELD("   ebx", r_ebx);
    PRINT_FIELD("   ecx", r_ecx);
    PRINT_FIELD("   edx", r_edx);
    PRINT_FIELD("   esi", r_esi);
    PRINT_FIELD("   edi", r_edi);
    PRINT_FIELD("   ebp", r_ebp);
    PRINT_FIELD("   esp", r_esp);
    PRINT_FIELD("    cs", r_cs);
    PRINT_FIELD("    ss", r_ss);
    PRINT_FIELD("    ds", r_ds);
    PRINT_FIELD("    es", r_es);
    PRINT_FIELD("    fs", r_fs);
    PRINT_FIELD("    gs", r_gs);
    // Unused: r_isp
    // Unused: r_trapno
    // Unused: r_err
    PRINT_FIELD("eflags", r_eflags);
#undef PRINT_FIELD

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
    print_i386_registers(&regs);
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
    print_i386_instruction(child, regs.r_eip);
}
