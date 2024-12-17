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
#include <sys/user.h>

#include "trace.h"

#if 0 // TODO
//
// Print current CPU instruction.
//
static void print_arm64_instruction(int child, unsigned long long address)
{
    // Read opcode from child process.
    // Max instruction size for arm64 architecture is 4 bytes.
    uint64_t code[1];
    errno = 0;
    code[0] = ptrace(PT_READ_I, child, (void*)address, 0);
    if (errno) {
        perror("PT_READ_I");
        exit(-1);
    }

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
static void print_arm64_registers(const struct gpregs *cur)
{
    static struct gpregs prev;

#define PRINT_FIELD(name, field) \
    if (cur->field != prev.field) { \
        printf("    " name " = %#lx\n", cur->field); \
    }

    PRINT_FIELD("    x0", gp_x[0]);
    PRINT_FIELD("    x1", gp_x[1]);
    PRINT_FIELD("    x2", gp_x[2]);
    PRINT_FIELD("    x3", gp_x[3]);
    PRINT_FIELD("    x4", gp_x[4]);
    PRINT_FIELD("    x5", gp_x[5]);
    PRINT_FIELD("    x6", gp_x[6]);
    PRINT_FIELD("    x7", gp_x[7]);
    PRINT_FIELD("    x8", gp_x[8]);
    PRINT_FIELD("    x9", gp_x[9]);
    PRINT_FIELD("   x10", gp_x[10]);
    PRINT_FIELD("   x11", gp_x[11]);
    PRINT_FIELD("   x12", gp_x[12]);
    PRINT_FIELD("   x13", gp_x[13]);
    PRINT_FIELD("   x14", gp_x[14]);
    PRINT_FIELD("   x15", gp_x[15]);
    PRINT_FIELD("   x16", gp_x[16]);
    PRINT_FIELD("   x17", gp_x[17]);
    PRINT_FIELD("   x18", gp_x[18]);
    PRINT_FIELD("   x19", gp_x[19]);
    PRINT_FIELD("   x20", gp_x[20]);
    PRINT_FIELD("   x21", gp_x[21]);
    PRINT_FIELD("   x22", gp_x[22]);
    PRINT_FIELD("   x23", gp_x[23]);
    PRINT_FIELD("   x24", gp_x[24]);
    PRINT_FIELD("   x25", gp_x[25]);
    PRINT_FIELD("   x26", gp_x[26]);
    PRINT_FIELD("   x27", gp_x[27]);
    PRINT_FIELD("   x28", gp_x[28]);
    PRINT_FIELD("   x29", gp_x[29]);
    PRINT_FIELD("   x30", gp_lr);

    PRINT_FIELD("    sp", gp_sp);
    PRINT_FIELD("   elr", gp_elr);
    PRINT_FIELD("  spsr", gp_spsr);
#undef PRINT_FIELD

    prev = *cur;
}
#endif

//
// Get CPU state.
// Print program counter, disassembled instruction and changed registers.
//
void print_cpu_state(int child)
{
#if 0 // TODO
    struct gpregs regs;

    errno = 0;
    if (ptrace(PT_GETREGS, child, (caddr_t)&regs, NT_PRSTATUS) < 0) {
        perror("PT_GETREGS");
        exit(-1);
    }
    print_arm64_registers(&regs);
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
    print_arm64_instruction(child, regs.gp_elr);
#endif
}
