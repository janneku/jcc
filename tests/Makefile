LINKER = cc

test1: test1.s
	$(LINKER) -o test1 test1.s

%.s: %.c
	../jcc $< >$@
