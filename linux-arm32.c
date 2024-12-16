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
#include <asm/ptrace.h>

#include "trace.h"

//
// Print current CPU instruction.
//
static void print_arm32_instruction(int child, unsigned address)
{
    // Read opcode from child process.
    // Max instruction size for arm32 architecture is 4 bytes.
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
    printf("0x%08x: ", address);
    if (count == 0) {
        printf("(unknown)\n");
    } else {
        switch (insn[0].size) {
        case 4:
            printf(" %04x", code[0]);
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
static void print_arm32_registers(const struct user_regs *cur)
{
    static struct user_regs prev;

#define PRINT_FIELD(name, field) \
    if (cur->field != prev.field) { \
        printf("    " name " = %#lx\n", cur->field); \
    }
    PRINT_FIELD("    r0", ARM_r0);
    // Unused: ARM_ORIG_r0
    PRINT_FIELD("    r1", ARM_r1);
    PRINT_FIELD("    r2", ARM_r2);
    PRINT_FIELD("    r3", ARM_r3);
    PRINT_FIELD("    r4", ARM_r4);
    PRINT_FIELD("    r5", ARM_r5);
    PRINT_FIELD("    r6", ARM_r6);
    PRINT_FIELD("    r7", ARM_r7);
    PRINT_FIELD("    r8", ARM_r8);
    PRINT_FIELD("    r9", ARM_r9);
    PRINT_FIELD("   r10", ARM_r10);
    PRINT_FIELD("    fp", ARM_fp);
    PRINT_FIELD("    ip", ARM_ip);
    PRINT_FIELD("    sp", ARM_sp);
    PRINT_FIELD("    lr", ARM_lr);
    PRINT_FIELD("  cpsr", ARM_cpsr);
#undef PRINT_FIELD

    prev = *cur;
}

//
// Get CPU state.
// Print program counter, disassembled instruction and changed registers.
//
void print_cpu_state(int child)
{
    struct user_regs regs;
    struct user_fpregs fpregs;
    struct iovec iov = { &regs, sizeof(regs) };

    errno = 0;
    if (ptrace(PTRACE_GETREGSET, child, (void*)NT_PRSTATUS, &iov) < 0) {
        perror("PTRACE_GETREGSET");
        exit(-1);
    }
    print_arm32_registers(&regs);
#if 0
    //TODO: print FP registers
    errno = 0;
    if (ptrace(PTRACE_GETFPREGS, child, NULL, &fpregs) < 0) {
        perror("PTRACE_GETFPREGS");
        exit(-1);
    }
    print_fpregs(&fpregs);
#endif
    print_arm32_instruction(child, regs.ARM_pc);
}
