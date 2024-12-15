#include "trace.h"

// Handle for disassembler.
csh disasm;

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: bintrace ./file");
        exit(-1);
    }

    // Initialize disassembler.
#if __x86_64__
    int status = cs_open(CS_ARCH_X86, CS_MODE_64, &disasm);
#elif __ARM_ARCH_ISA_ARM
    int status = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &disasm);
#else
#   error "This architecture is not supported"
#endif
    if (status != CS_ERR_OK) {
        perror("cs_open");
        exit(-1);
    }

    trace(argv[1]);

    cs_close(&disasm);
}
