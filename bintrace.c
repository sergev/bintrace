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
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <capstone/capstone.h>
#include <asm/ptrace.h>

// Handle for disassembler.
csh disasm;

//
// Print current CPU instruction.
//
void print_arm32_instruction(int child, unsigned address)
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
            perror("PTRACE_GETFPREGS");
            exit(-1);
        }
        printf("   %s %s\n", insn[0].mnemonic, insn[0].op_str);
        cs_free(insn, count);
    }
}

#if 0
//
// Get CPU state.
// Print program counter, disassembled instruction and changed registers.
//
void print_arm32_registers(const struct user_regs_struct *cur)
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
#define ARM_cpsr  uregs[16]
#define ARM_pc        uregs[15]
#define ARM_lr        uregs[14]
#define ARM_sp        uregs[13]
#define ARM_ip        uregs[12]
#define ARM_fp        uregs[11]
#define ARM_r10       uregs[10]
#define ARM_r9        uregs[9]
#define ARM_r8        uregs[8]
#define ARM_r7        uregs[7]
#define ARM_r6        uregs[6]
#define ARM_r5        uregs[5]
#define ARM_r4        uregs[4]
#define ARM_r3        uregs[3]
#define ARM_r2        uregs[2]
#define ARM_r1        uregs[1]
#define ARM_r0        uregs[0]
#define ARM_ORIG_r0   uregs[17]
#endif

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
    //print_arm32_registers(&regs);
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

//
// Wait for child process to stop on next instruction.
// Return true when the child process is still running.
// Return false when in terminated for some reason.
//
bool child_alive()
{
    int status;
    if (wait(&status) < 0) {
        perror("wait");
        exit(-1);
    }
    //printf("%zu: status %#x\n", instr_count, status);

    if (WIFEXITED(status)) {
        // The process terminated normally by a call to _exit(2).
        if (WEXITSTATUS(status) == 0) {
            printf("Process exited normally.\n");
        } else {
            printf("Process exited with status %d\n", WEXITSTATUS(status));
        }
        return false;
    }

    if (WIFSIGNALED(status)) {
        // The process terminated due to receipt of a signal.
        printf("Child killed by signal %s\n", strsignal(WTERMSIG(status)));
        if (WCOREDUMP(status)) {
            printf("Core dumped.\n");
        }
        return false;
    }

    // The process must have stopped, being traced.
    if (!WIFSTOPPED(status)) {
        printf("Child not stopped?\n");
        exit(-1);
    }

    // WSTOPSIG(status) evaluates to the signal that caused the process to stop.
    // Must be SIGTRAP for ptrace.
    if (WSTOPSIG(status) != SIGTRAP) {
        printf("Child stopped by signal %s\n", strsignal(WSTOPSIG(status)));
        return false;
    }

    // Child stopped by SIGTRAP, as expected.
    return true;
}

void trace(char *pathname)
{
    // Create child.
    pid_t child = fork();
    if (child < 0) {
        // Cannot fork
        perror("fork");
        exit(-1);
    }

    if (child == 0) {
        //
        // Child: start target program.
        //
        printf("Starting program: %s\n", pathname);

        errno = 0;
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("PTRACE_TRACEME");
            exit(-1);
        }
        char *const argv[] = { pathname, NULL };
        execv(pathname, argv);

        // Failed to execute.
        perror(pathname);
        exit(-1);
    }

    //
    // Parent.
    //
    size_t instr_count = 0;
    while (child_alive()) {

        print_cpu_state(child);
        instr_count += 1;

        // Execute next CPU instruction.
        fflush(stdout);
        errno = 0;
        if (ptrace(PTRACE_SINGLESTEP, child, NULL, NULL) < 0) {
            perror("PTRACE_SINGLESTEP");
            exit(-1);
        }
    }
}

int main()
{
    // Initialize disassembler.
    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &disasm) != CS_ERR_OK) {
        perror("cs_open");
        exit(-1);
    }

    trace("./hello-arm32-linux");

    cs_close(&disasm);
}
