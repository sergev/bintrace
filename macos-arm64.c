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

//
// Print current CPU instruction.
//
static void print_arm64_instruction(int child, unsigned long long address)
{
    // Read opcode from child process.
    // Max instruction size for arm64 architecture is 4 bytes.
    uint32_t code[1];
    vm_size_t got_nbytes;
    kern_return_t status = vm_read_overwrite(macos_port, address, sizeof(code), (vm_address_t)code, &got_nbytes);
    if (status != KERN_SUCCESS) {
        printf("vm_read failed: %s\n", mach_error_string(status));
        exit(-1);
    }
    if (got_nbytes != sizeof(code)) {
        printf("vm_read: got wrong amount\n");
        exit(-1);
    }
printf("0x%016llx: 0x%08x\n", address, code[0]);

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
static void print_arm64_registers(const arm_thread_state64_t *cur)
{
    static arm_thread_state64_t prev;

#define PRINT_FIELD(name, field) \
    if (cur->field != prev.field) { \
        printf("    " name " = %#llx\n", cur->field); \
    }

    PRINT_FIELD("    x0", __x[0]);
    PRINT_FIELD("    x1", __x[1]);
    PRINT_FIELD("    x2", __x[2]);
    PRINT_FIELD("    x3", __x[3]);
    PRINT_FIELD("    x4", __x[4]);
    PRINT_FIELD("    x5", __x[5]);
    PRINT_FIELD("    x6", __x[6]);
    PRINT_FIELD("    x7", __x[7]);
    PRINT_FIELD("    x8", __x[8]);
    PRINT_FIELD("    x9", __x[9]);
    PRINT_FIELD("   x10", __x[10]);
    PRINT_FIELD("   x11", __x[11]);
    PRINT_FIELD("   x12", __x[12]);
    PRINT_FIELD("   x13", __x[13]);
    PRINT_FIELD("   x14", __x[14]);
    PRINT_FIELD("   x15", __x[15]);
    PRINT_FIELD("   x16", __x[16]);
    PRINT_FIELD("   x17", __x[17]);
    PRINT_FIELD("   x18", __x[18]);
    PRINT_FIELD("   x19", __x[19]);
    PRINT_FIELD("   x20", __x[20]);
    PRINT_FIELD("   x21", __x[21]);
    PRINT_FIELD("   x22", __x[22]);
    PRINT_FIELD("   x23", __x[23]);
    PRINT_FIELD("   x24", __x[24]);
    PRINT_FIELD("   x25", __x[25]);
    PRINT_FIELD("   x26", __x[26]);
    PRINT_FIELD("   x27", __x[27]);
    PRINT_FIELD("   x28", __x[28]);

    uintptr_t new_fp = arm_thread_state64_get_fp(*cur);
    uintptr_t new_lr = arm_thread_state64_get_lr(*cur);
    uintptr_t new_sp = arm_thread_state64_get_sp(*cur);
    if (new_fp != prev.__fp) {
        printf("        fp = %#jx\n", new_fp);
    }
    if (new_lr != prev.__lr) {
        printf("        lr = %#jx\n", new_lr);
    }
    if (new_sp != prev.__sp) {
        printf("        sp = %#jx\n", new_sp);
    }

    if (cur->__cpsr != prev.__cpsr) {
        printf("      cpsr = %#x\n", cur->__cpsr);
    }

#undef PRINT_FIELD
    prev = *cur;
    prev.__fp = new_fp;
    prev.__lr = new_lr;
    prev.__sp = new_sp;
}

//
// Get CPU state.
// Print program counter, disassembled instruction and changed registers.
//
void print_cpu_state(int child)
{
    arm_thread_state64_t regs;
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;

    kern_return_t status = thread_get_state(macos_child, ARM_THREAD_STATE64, (thread_state_t)&regs, &count);
    if (status != KERN_SUCCESS) {
        printf("thread_get_state failed: %s\n", mach_error_string(status));
        exit(-1);
    }
    status = thread_convert_thread_state(macos_child, THREAD_CONVERT_THREAD_STATE_TO_SELF,
                                         ARM_THREAD_STATE64, (thread_state_t)&regs, count,
                                         (thread_state_t)&regs, &count);
    if (status != KERN_SUCCESS) {
        printf("thread_convert_thread_state failed: %s\n", mach_error_string(status));
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
    print_arm64_instruction(child, arm_thread_state64_get_pc(regs));
}
