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
#include <mach/mach.h>

#include "trace.h"

extern task_t macos_port;
extern thread_act_t macos_child;

//#define PAGE_ALIGN(addr) (vm_address_t)((uintptr_t)(addr) & (~(vm_page_size - 1)))

//
// Print current CPU instruction.
//
static void print_amd64_instruction(int child, unsigned long long address)
{
//TODO: read user code
//printf("0x%016llx:\n", address);
    // Read opcode from child process.
//    kern_return_t status = vm_protect(macos_port, PAGE_ALIGN(address), vm_page_size, false, VM_PROT_READ | VM_PROT_EXECUTE);
//    if (status != KERN_SUCCESS) {
//        printf("vm_protect failed: %s\n", mach_error_string(status));
//        return;
//    }

    // Max instruction size for x86-64 architecture is 16 bytes.
    uint64_t code[2];
    mach_msg_type_number_t got_nbytes;
    kern_return_t status = vm_read(macos_port, address, sizeof(code), (vm_offset_t*)code, &got_nbytes);
    if (status != KERN_SUCCESS) {
        printf("vm_read failed: %s\n", mach_error_string(status));
        exit(-1);
    }
    if (got_nbytes != sizeof(code)) {
        printf("vm_read: got wrong amount\n");
        exit(-1);
    }
printf("0x%016llx: %08llx %08llx\n", address, code[0], code[1]);

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
}

//
// Get CPU state.
// Print program counter, disassembled instruction and changed registers.
//
static void print_amd64_registers(const x86_thread_state64_t *cur)
{
    static x86_thread_state64_t prev;

#define PRINT_FIELD(name, field) \
    if (cur->field != prev.field) { \
        printf("    " name " = %#llx\n", cur->field); \
    }

    PRINT_FIELD("   rax", __rax);
    PRINT_FIELD("   rbx", __rbx);
    PRINT_FIELD("   rcx", __rcx);
    PRINT_FIELD("   rdx", __rdx);
    PRINT_FIELD("   rsi", __rsi);
    PRINT_FIELD("   rdi", __rdi);
    PRINT_FIELD("   rbp", __rbp);
    PRINT_FIELD("   rsp", __rsp);

    PRINT_FIELD("    r8", __r8);
    PRINT_FIELD("    r9", __r9);
    PRINT_FIELD("   r10", __r10);
    PRINT_FIELD("   r11", __r11);
    PRINT_FIELD("   r12", __r12);
    PRINT_FIELD("   r13", __r13);
    PRINT_FIELD("   r14", __r14);
    PRINT_FIELD("   r15", __r15);

    PRINT_FIELD("    cs", __cs);
    PRINT_FIELD("    fs", __fs);
    PRINT_FIELD("    gs", __gs);

    PRINT_FIELD("eflags", __rflags);

#undef PRINT_FIELD
    prev = *cur;
}

//
// Get CPU state.
// Print program counter, disassembled instruction and changed registers.
//
void print_cpu_state(int child)
{
    x86_thread_state64_t regs;
    mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;

    kern_return_t status = thread_get_state(macos_child, x86_THREAD_STATE64, (thread_state_t)&regs, &count);
    if (status != KERN_SUCCESS) {
        printf("thread_get_state failed: %s\n", mach_error_string(status));
        exit(-1);
    }
    status = thread_convert_thread_state(macos_child, THREAD_CONVERT_THREAD_STATE_TO_SELF,
                                         x86_THREAD_STATE64, (thread_state_t)&regs, count,
                                         (thread_state_t)&regs, &count);
    if (status != KERN_SUCCESS) {
        printf("thread_convert_thread_state failed: %s\n", mach_error_string(status));
        exit(-1);
    }
    print_amd64_registers(&regs);
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
    print_amd64_instruction(child, regs.__rip);
}
