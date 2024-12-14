#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
//#include <sys/personality.h> TODO
#include <capstone/capstone.h>

// Handle for disassembler.
csh disasm;

//
// Print current CPU instruction.
//
void print_cpu_instruction(int child, unsigned long long address)
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
void print_cpu_registers(const struct user_regs_struct *cur)
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
    print_cpu_registers(&regs);
#if 0
    if (ptrace(PTRACE_GETFPREGS, child, NULL, &fpregs) < 0) {
        perror("PTRACE_GETFPREGS");
        exit(-1);
    }
    print_fpregs(&fpregs);
#endif
    print_cpu_instruction(child, regs.rip);
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
    // Initialize disassembler.
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &disasm) != CS_ERR_OK) {
        perror("cs_open");
        exit(-1);
    }

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
        errno = 0;
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("PTRACE_TRACEME");
            exit(-1);
        }
        //personality(ADDR_NO_RANDOMIZE);
        char *const argv[] = { pathname, NULL };
        printf("Starting program: %s\n", pathname);
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
        if (ptrace(PTRACE_SINGLESTEP, child, NULL, NULL) < 0) {
            perror("PTRACE_SINGLESTEP");
            exit(-1);
        }
    }
    cs_close(&disasm);
}

int main()
{
    trace("./hello-amd64-linux");
}
