LINKER = cc

all: test1 test2

test1: test1.s
	$(LINKER) -o test1 test1.s

test2: test2.s
	$(LINKER) -o test2 test2.s

%.s: %.c
	../jcc $< >$@
