#
# Architectures:
#       x86-64  working
#       i386    todo
#       arm64   working
#       arm32   todo
#       riscv64 todo
#       mips32  todo
#
PROG = bintrace hello-arm64-linux
LIBS = -lcapstone

all:    $(PROG)

clean:
	rm -f *.o *.dis *.trace $(PROG)

%.o:    %.S
	cpp $< | as -o $@ -

bintrace: bintrace.o
	$(CC) $(LDFLAGS) -o $@ $< $(LIBS)

hello-arm64-linux: hello-arm64-linux.o
	ld -o $@ $<
	objdump -D $@ > $@.dis
