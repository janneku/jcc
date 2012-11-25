LINKER = cc

all: test1 test2 test3

test1: test1.s
	$(LINKER) -o test1 test1.s -g

test2: test2.s
	$(LINKER) -o test2 test2.s -g

test3: test3.s
	$(LINKER) -o test3 test3.s -g

%.s: %.c
	../jcc $< >$@
