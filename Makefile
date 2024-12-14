#
# Architectures:
#       amd64   working
#       i386    todo
#       arm64   todo
#       arm32   todo
#       riscv64 todo
#       mips32  todo
#
PROG = bintrace hello-amd64-linux
LIBS = -lcapstone

all:    $(PROG)

clean:
	rm -f *.o *.dis *.trace $(PROG)

%.o:    %.S
	cpp $< | as -o $@ -

bintrace: bintrace.o
	$(CC) $(LDFLAGS) -o $@ $< $(LIBS)

hello-amd64-linux: hello-amd64-linux.o
	ld -o $@ $<
	objdump -D $@ > $@.dis
