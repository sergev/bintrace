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
    code[0] = ptrace(PTRACE_PEEKTEXT, child, (void*)address, NULL);
    code[1] = ptrace(PTRACE_PEEKTEXT, child, (void*)(address + 4), NULL);
    code[2] = ptrace(PTRACE_PEEKTEXT, child, (void*)(address + 8), NULL);
    code[3] = ptrace(PTRACE_PEEKTEXT, child, (void*)(address + 12), NULL);
    if (errno) {
        perror("PTRACE_PEEKTEXT");
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
static void print_i386_registers(const struct user_regs_struct *cur)
{
    static struct user_regs_struct prev;

#define PRINT_FIELD(name, field) \
    if (cur->field != prev.field) { \
        fprintf(out, "    " name " = %#lx\n", cur->field); \
    }
    PRINT_FIELD("   eax", eax);
    PRINT_FIELD("   ebx", ebx);
    PRINT_FIELD("   ecx", ecx);
    PRINT_FIELD("   edx", edx);
    PRINT_FIELD("   esi", esi);
    PRINT_FIELD("   edi", edi);
    PRINT_FIELD("   ebp", ebp);
    PRINT_FIELD("   esp", esp);
    PRINT_FIELD("    cs", xcs);
    PRINT_FIELD("    ss", xss);
    PRINT_FIELD("    ds", xds);
    PRINT_FIELD("    es", xes);
    PRINT_FIELD("    fs", xfs);
    PRINT_FIELD("    gs", xgs);
    // Unused: orig_eax
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

    errno = 0;
    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0) {
        perror("PTRACE_GETREGS");
        exit(-1);
    }
    print_i386_registers(&regs);
#if 0
    //TODO: print FP registers
    errno = 0;
    if (ptrace(PTRACE_GETFPREGS, child, NULL, &fpregs) < 0) {
        perror("PTRACE_GETFPREGS");
        exit(-1);
    }
    print_fpregs(&fpregs);
#endif
    print_i386_instruction(child, regs.eip);
}
