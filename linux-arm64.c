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
// On syscall, ptrace() stops twice: right before execution and after it.
// With this flag we ignore the first stop.
//
static bool before_syscall;

//
// Print current CPU instruction.
//
static void print_arm64_instruction(int child, unsigned long long address)
{
    // Read opcode from child process.
    // Max instruction size for arm64 architecture is 4 bytes.
    uint64_t code[1];
    errno = 0;
    code[0] = ptrace(PTRACE_PEEKTEXT, child, (void*)address, NULL);
    if (errno) {
        perror("PTRACE_PEEKTEXT");
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

    if ((uint32_t)code[0] == 0xd4000001) {
        // Next stop will be "before" a syscall: ignore it.
        before_syscall = true;
    }
}

//
// Get CPU state.
// Print program counter, disassembled instruction and changed registers.
//
static void print_arm64_registers(const struct user_regs_struct *cur)
{
    static struct user_regs_struct prev;

#define PRINT_FIELD(name, field) \
    if (cur->field != prev.field) { \
        printf("    " name " = %#llx\n", cur->field); \
    }

    PRINT_FIELD("    r0", regs[0]);
    PRINT_FIELD("    r1", regs[1]);
    PRINT_FIELD("    r2", regs[2]);
    PRINT_FIELD("    r3", regs[3]);
    PRINT_FIELD("    r4", regs[4]);
    PRINT_FIELD("    r5", regs[5]);
    PRINT_FIELD("    r6", regs[6]);
    PRINT_FIELD("    r7", regs[7]);
    PRINT_FIELD("    r8", regs[8]);
    PRINT_FIELD("    r9", regs[9]);
    PRINT_FIELD("   r10", regs[10]);
    PRINT_FIELD("   r11", regs[11]);
    PRINT_FIELD("   r12", regs[12]);
    PRINT_FIELD("   r13", regs[13]);
    PRINT_FIELD("   r14", regs[14]);
    PRINT_FIELD("   r15", regs[15]);
    PRINT_FIELD("   r16", regs[16]);
    PRINT_FIELD("   r17", regs[17]);
    PRINT_FIELD("   r18", regs[18]);
    PRINT_FIELD("   r19", regs[19]);
    PRINT_FIELD("   r20", regs[20]);
    PRINT_FIELD("   r21", regs[21]);
    PRINT_FIELD("   r22", regs[22]);
    PRINT_FIELD("   r23", regs[23]);
    PRINT_FIELD("   r24", regs[24]);
    PRINT_FIELD("   r25", regs[25]);
    PRINT_FIELD("   r26", regs[26]);
    PRINT_FIELD("   r27", regs[27]);
    PRINT_FIELD("   r28", regs[28]);
    PRINT_FIELD("   r29", regs[29]);
    PRINT_FIELD("   r30", regs[30]);
    PRINT_FIELD("    sp", sp);
    PRINT_FIELD("pstate", pstate);
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
    struct user_fpsimd_struct fpregs;
    struct iovec iov = { &regs, sizeof(regs) };

    if (before_syscall) {
        // We are right before execution of a syscall.
        // Ignore this stop and wait for another one.
        before_syscall = false;
        return;
    }

    errno = 0;
    if (ptrace(PTRACE_GETREGSET, child, (void*)NT_PRSTATUS, &iov) < 0) {
        perror("PTRACE_GETREGSET");
        exit(-1);
    }
    print_arm64_registers(&regs);
#if 0
    //TODO: print FP registers
    errno = 0;
    if (ptrace(PTRACE_GETFPREGS, child, NULL, &fpregs) < 0) {
        perror("PTRACE_GETFPREGS");
        exit(-1);
    }
    print_fpregs(&fpregs);
#endif
    print_arm64_instruction(child, regs.pc);
}
