# Tests makefile

sources = arithmetic.asm mov.asm

all: $(basename $(sources))

$(basename $(sources)): % : %.asm
	nasm -o $@ -f bin $<

.PHONY: clean
clean:
	rm -f $(basename $(sources))
