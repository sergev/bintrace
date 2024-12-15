#
# Architectures:
#       x86_64=amd64    working
#       i386            todo
#       arm64=aarch64   todo
#       arm32=armv7l    todo
#       riscv64         todo
#       mips32          todo
#
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
