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
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/procctl.h>

#include "trace.h"

//
// Wait for child process to stop on next instruction.
// Return true when the child process is still running.
// Return false when in terminated for some reason.
//
static bool child_alive()
{
    int status;
    if (wait(&status) < 0) {
        perror("wait");
        exit(-1);
    }

    if (WIFEXITED(status)) {
        // The process terminated normally by a call to _exit(2).
        if (WEXITSTATUS(status) == 0) {
            fprintf(out, "Process exited normally.\n");
        } else {
            fprintf(out, "Process exited with status %d\n", WEXITSTATUS(status));
        }
        return false;
    }

    if (WIFSIGNALED(status)) {
        // The process terminated due to receipt of a signal.
        fprintf(out, "Child killed by signal %s\n", strsignal(WTERMSIG(status)));
        if (WCOREDUMP(status)) {
            fprintf(out, "Core dumped.\n");
        }
        return false;
    }

    // The process must have stopped, being traced.
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "Child not stopped?\n");
        exit(-1);
    }

    // WSTOPSIG(status) evaluates to the signal that caused the process to stop.
    // Must be SIGTRAP for ptrace.
    if (WSTOPSIG(status) != SIGTRAP) {
        fprintf(out, "Child stopped by signal %s\n", strsignal(WSTOPSIG(status)));
        return false;
    }

    // Child stopped by SIGTRAP, as expected.
    return true;
}

void trace(char *const argv[])
{
    fprintf(out, "Starting program: %s\n", argv[0]);

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
        // Disable address-space-layout randomization.
        //
        int data = PROC_ASLR_FORCE_DISABLE;
        procctl(P_PID, 0, PROC_ASLR_CTL, &data);

        errno = 0;
        if (ptrace(PT_TRACE_ME, 0, NULL, 0) < 0) {
            perror("PT_TRACE_ME");
            exit(-1);
        }
        execvp(argv[0], argv);

        // Failed to execute.
        perror(argv[0]);
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
        if (ptrace(PT_STEP, child, NULL, 0) < 0) {
            if (errno != EIO && errno != EOPNOTSUPP) {
                perror("PT_STEP");
                exit(-1);
            } else {
                // Single stepping is not supported for this architecture.
                // Use syscall tracing instead.
                errno = 0;
                if (ptrace(PT_SYSCALL, child, (caddr_t)1, 0) < 0) {
                    perror("PT_SYSCALL");
                    exit(-1);
                }
            }
        }
    }
}
