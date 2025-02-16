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
#include <asm/ptrace.h>

#include "trace.h"

//
// Print current CPU instruction.
//
static void print_powerpc32_instruction(int child, unsigned address)
{
    // Read opcode from child process.
    // Max instruction size for powerpc32 architecture is 4 bytes.
    uint32_t code[1];
    errno = 0;
    code[0] = ptrace(PTRACE_PEEKTEXT, child, (void*)address, NULL);
    if (errno) {
        perror("PTRACE_PEEKTEXT");
        exit(-1);
    }

    // Disassemble one instruction.
    cs_insn *insn = NULL;
    size_t count = cs_disasm(disasm, (uint8_t*)code, sizeof(code), address, 1, &insn);
    fprintf(out, "0x%08x: ", address);
    if (count == 0) {
        fprintf(out, "(unknown)\n");
    } else {
        switch (insn[0].size) {
        case 4:
            fprintf(out, " %04x", code[0]);
            break;
        case 2:
            fprintf(out, " %02x    ", (uint16_t)code[0]);
            break;
        default:
            fprintf(stderr, "Unexpected instruction size: %u bytes\n", insn[0].size);
            exit(-1);
        }
        fprintf(out, "   %s %s\n", insn[0].mnemonic, insn[0].op_str);
        cs_free(insn, count);
    }
}

//
// Get CPU state.
// Print program counter, disassembled instruction and changed registers.
//
static void print_powerpc32_registers(const struct pt_regs *cur)
{
    static struct pt_regs prev;

#define PRINT_FIELD(name, field) \
    if (cur->field != prev.field) { \
        fprintf(out, "    " name " = %#lx\n", cur->field); \
    }
    PRINT_FIELD("      r0", gpr[0]);
    PRINT_FIELD("      r1", gpr[1]);
    PRINT_FIELD("      r2", gpr[2]);
    PRINT_FIELD("      r3", gpr[3]);
    PRINT_FIELD("      r4", gpr[4]);
    PRINT_FIELD("      r5", gpr[5]);
    PRINT_FIELD("      r6", gpr[6]);
    PRINT_FIELD("      r7", gpr[7]);
    PRINT_FIELD("      r8", gpr[8]);
    PRINT_FIELD("      r9", gpr[9]);
    PRINT_FIELD("     r10", gpr[10]);
    PRINT_FIELD("     r11", gpr[11]);
    PRINT_FIELD("     r12", gpr[12]);
    PRINT_FIELD("     r13", gpr[13]);
    PRINT_FIELD("     r14", gpr[14]);
    PRINT_FIELD("     r15", gpr[15]);
    PRINT_FIELD("     r16", gpr[16]);
    PRINT_FIELD("     r17", gpr[17]);
    PRINT_FIELD("     r18", gpr[18]);
    PRINT_FIELD("     r19", gpr[19]);
    PRINT_FIELD("     r20", gpr[20]);
    PRINT_FIELD("     r21", gpr[21]);
    PRINT_FIELD("     r22", gpr[22]);
    PRINT_FIELD("     r23", gpr[23]);
    PRINT_FIELD("     r24", gpr[24]);
    PRINT_FIELD("     r25", gpr[25]);
    PRINT_FIELD("     r26", gpr[26]);
    PRINT_FIELD("     r27", gpr[27]);
    PRINT_FIELD("     r28", gpr[28]);
    PRINT_FIELD("     r29", gpr[29]);
    PRINT_FIELD("     r30", gpr[30]);
    PRINT_FIELD("     r31", gpr[31]);

    PRINT_FIELD("     msr", msr);
    PRINT_FIELD("     ctr", ctr);
    PRINT_FIELD("     link", link);
    PRINT_FIELD("     xer", xer);
    PRINT_FIELD("     ccr", ccr);
#undef PRINT_FIELD

    prev = *cur;
}

//
// Get CPU state.
// Print program counter, disassembled instruction and changed registers.
//
void print_cpu_state(int child)
{
    struct pt_regs regs;

    errno = 0;
    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0) {
        perror("PTRACE_GETREGS");
        exit(-1);
    }
    print_powerpc32_registers(&regs);
#if 0
    //TODO: print FP registers
    struct user_fpregs fpregs;
    errno = 0;
    if (ptrace(PTRACE_GETFPREGS, child, NULL, &fpregs) < 0) {
        perror("PTRACE_GETFPREGS");
        exit(-1);
    }
    print_fpregs(&fpregs);
#endif
    print_powerpc32_instruction(child, regs.nip);
}
