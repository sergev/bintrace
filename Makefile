#
# Architectures:
#       arm32   working
#       i386    todo
#       arm64   working
#       arm32   no single-step in kernel
#       riscv64 no single-step in kernel
#       mips32  no single-step in kernel
#
PROG = bintrace hello-arm32-linux
LIBS = -lcapstone

all:    $(PROG)

clean:
	rm -f *.o *.dis *.trace $(PROG)

%.o:    %.S
	cpp $< | as -o $@ -

bintrace: bintrace.o
	$(CC) $(LDFLAGS) -o $@ $< $(LIBS)

hello-arm32-linux: hello-arm32-linux.o
	ld -o $@ $<
	objdump -D $@ > $@.dis
