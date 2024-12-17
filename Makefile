PROG    = bintrace
LIBS    = -lcapstone
OBJS    = main.o
ARCH    := $(shell uname -m)
OS      := $(shell uname -s)
BRANDELF = size
DEMO     = ./$(PROG)

ifeq ($(OS), Linux)
    ifeq ($(ARCH), x86_64)
        # Linux on Intel 64-bit architecture
        TEST = demo-amd64-linux
        OBJS += trace-linux.o linux-amd64.o
    endif
    ifeq ($(ARCH), i686)
        # Linux on Intel 32-bit architecture
        TEST = demo-i386-linux
        OBJS += trace-linux.o linux-i386.o
    endif
    ifeq ($(ARCH), aarch64)
        # Linux on ARM64 architecture
        TEST = demo-arm64-linux
        OBJS += trace-linux.o linux-arm64.o
    endif
    ifeq ($(ARCH), armv7l)
        # Linux on ARM32 architecture
        TEST = demo-arm32-linux
        OBJS += trace-linux.o linux-arm32.o
    endif
    ifeq ($(ARCH), riscv64)
        # Linux on RISC-V 64-bit architecture
        TEST = demo-riscv64-linux
        OBJS += trace-linux.o linux-riscv64.o
    endif
endif
ifeq ($(OS), FreeBSD)
    CFLAGS += -I/usr/local/include
    LIBS += -L/usr/local/lib
    BRANDELF = brandelf -t FreeBSD
    ifeq ($(ARCH), amd64)
        # FreeBSD on Intel 64-bit architecture
        TEST = demo-amd64-freebsd
        OBJS += trace-freebsd.o freebsd-amd64.o
    endif
    ifeq ($(ARCH), i386)
        # FreeBSD on Intel 32-bit architecture
        TEST = demo-i386-freebsd
        OBJS += trace-freebsd.o freebsd-i386.o
    endif
    ifeq ($(ARCH), arm64)
        # FreeBSD on ARM64 architecture
        TEST = demo-arm64-freebsd
        OBJS += trace-freebsd.o freebsd-arm64.o
    endif
    ifeq ($(ARCH), arm)
        # FreeBSD on ARM32 architecture
        TEST = demo-arm32-freebsd
        OBJS += trace-freebsd.o freebsd-arm32.o
    endif
endif
ifeq ($(OS), Darwin)
    CFLAGS += -I/opt/homebrew/include
    LIBS += -sectcreate __TEXT __info_plist ./app.plist
    #TODO: BRANDELF = codesign -s $(file < ~/.my_codesign_identity)
    DEMO = sudo ./$(PROG)
    ifeq ($(ARCH), x86_64)
        # MacOS on Intel 64-bit architecture
        TEST = demo-amd64-macos
        OBJS += trace-macos.o macos-amd64.o
    endif
    ifeq ($(ARCH), arm64)
        # MacOS on Apple ARM64 processor
        TEST = demo-arm64-macos
        OBJS += trace-macos.o macos-arm64.o
        LIBS += -L/opt/homebrew/lib
    endif
endif

all:    $(PROG) $(TEST) demo.sh

clean:
	rm -f *.o *.dis *.trace $(PROG) demo-*-linux demo-*-macos demo-*-freebsd demo.sh

%.o:    %.S
	cpp $< | as -o $@ -

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

$(TEST): $(TEST).o
	ld -o $@ $<
	$(BRANDELF) $@
	objdump -D $@ > $@.dis

demo.sh:
	echo "$(DEMO) ./$(TEST)" > $@
	chmod +x $@
