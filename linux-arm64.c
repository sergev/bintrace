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

uint32_t last_opcode;

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
    last_opcode = code[0];

    // Disassemble one instruction.
    cs_insn *insn = NULL;
    size_t count = cs_disasm(disasm, (uint8_t*)code, sizeof(code), address, 1, &insn);
    fprintf(out, "0x%016llx: ", address);
    if (count == 0) {
        fprintf(out, "(unknown)\n");
    } else {
        switch (insn[0].size) {
        case 4:
            fprintf(out, " %04x", (uint32_t)code[0]);
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
        fprintf(out, "    " name " = %#lx\n", cur->field); \
    }

    PRINT_FIELD("    x0", regs[0]);
    PRINT_FIELD("    x1", regs[1]);
    PRINT_FIELD("    x2", regs[2]);
    PRINT_FIELD("    x3", regs[3]);
    PRINT_FIELD("    x4", regs[4]);
    PRINT_FIELD("    x5", regs[5]);
    PRINT_FIELD("    x6", regs[6]);
    PRINT_FIELD("    x7", regs[7]);
    PRINT_FIELD("    x8", regs[8]);
    PRINT_FIELD("    x9", regs[9]);
    PRINT_FIELD("   x10", regs[10]);
    PRINT_FIELD("   x11", regs[11]);
    PRINT_FIELD("   x12", regs[12]);
    PRINT_FIELD("   x13", regs[13]);
    PRINT_FIELD("   x14", regs[14]);
    PRINT_FIELD("   x15", regs[15]);
    PRINT_FIELD("   x16", regs[16]);
    PRINT_FIELD("   x17", regs[17]);
    PRINT_FIELD("   x18", regs[18]);
    PRINT_FIELD("   x19", regs[19]);
    PRINT_FIELD("   x20", regs[20]);
    PRINT_FIELD("   x21", regs[21]);
    PRINT_FIELD("   x22", regs[22]);
    PRINT_FIELD("   x23", regs[23]);
    PRINT_FIELD("   x24", regs[24]);
    PRINT_FIELD("   x25", regs[25]);
    PRINT_FIELD("   x26", regs[26]);
    PRINT_FIELD("   x27", regs[27]);
    PRINT_FIELD("   x28", regs[28]);
    PRINT_FIELD("   x29", regs[29]);
    PRINT_FIELD("   x30", regs[30]);

    PRINT_FIELD("    sp", sp);
    PRINT_FIELD("  cpsr", pstate);
#undef PRINT_FIELD

    prev = *cur;
}

//
// Detect STXR instruction.
// For example:
//      88117c41    stxr w17, w1,  [x2]
//      8811fc30   stlxr w17, w16, [x1]
//                       rd,  rt,  [rn]
// Bits:
//      3322 2222 2222 1111 1111 11
//      1098-7654-3210-9876-5432-1098-7654-3210
//      8    8    1    1    7    c    4    1
//      1x00 1000 000x xxxx 0111 11xx xxxx xxxx
//      \/           \____/        \____/\____/
//      size           rs            rn    rt
//      1011 1111 1110 0000 0000 0000 0000 0000 bitmask
//
static bool is_stxr()
{
    return (last_opcode & 0xbfe00000) == 0x88000000;
}

//
// Clear result of STXR, as if it succeeded.
//
// stxr rd, rt, [rn]
//
static void hack_stxr(int child, struct user_regs_struct *regs)
{
    unsigned rs = (last_opcode >> 16) & 0x1f;
    unsigned rt = last_opcode & 0x1f;
    unsigned rn = (last_opcode >> 5) & 0x1f;

    if (rs < 31 && rt < 31 && regs->regs[rs] != 0) {
        uint64_t rt_value = regs->regs[rt];
        uint64_t rn_value = (rn == 31) ? regs->sp : regs->regs[rn];
        fprintf(out, "   hack stxr: write 0x%08lx to [0x%016lx]\n", rt_value, rn_value);
        regs->regs[rs] = 0;

        struct iovec iov = { regs, sizeof(*regs) };
        errno = 0;
        if (ptrace(PTRACE_SETREGSET, child, (void*)NT_PRSTATUS, &iov) < 0) {
            perror("PTRACE_SETREGSET");
            exit(-1);
        }

        //TODO: size 64bit/32bit
        errno = 0;
        ptrace(PTRACE_POKEDATA, child, (void*)rn_value, rt_value);
        if (errno) {
            perror("PTRACE_POKEDATA");
            exit(-1);
        }
    }
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
    if (is_stxr()) {
        hack_stxr(child, &regs);
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
