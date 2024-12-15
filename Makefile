PROG    = bintrace
LIBS    = -lcapstone
OBJS    = main.o trace.o
ARCH    := $(shell uname -m)

ifeq ($(ARCH), x86_64)
    # Intel 64-bit architecture
    TEST = hello-amd64-linux
    OBJS += arch-amd64.o
endif
ifeq ($(ARCH), aarch64)
    # ARM64 architecture
    TEST = hello-arm64-linux
    OBJS += arch-arm64.o
endif
ifeq ($(ARCH), armv7l)
    # ARM32 architecture
    TEST = hello-arm32-linux
    OBJS += arch-arm32.o
endif
ifeq ($(ARCH), riscv64)
    # RISC-V 64-bit architecture
    TEST = hello-riscv64-linux
    OBJS += arch-riscv64.o
endif

all:    $(PROG) $(TEST) demo.sh

clean:
	rm -f *.o *.dis *.trace $(PROG) hello-*-linux demo.sh

%.o:    %.S
	cpp $< | as -o $@ -

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

$(TEST): $(TEST).o
	ld -o $@ $<
	objdump -D $@ > $@.dis

demo.sh:
	echo "./$(PROG) ./$(TEST)" > $@
	chmod +x $@
