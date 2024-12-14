#
# Architectures:
#       arm32   working
#       i386    todo
#       arm64   todo
#       arm32   todo
#       riscv64 todo
#       mips32  todo
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
