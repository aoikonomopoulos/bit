# Tests makefile

tests = add sub mov

all: $(tests)

add: add.asm
	nasm -o $@ -f bin $<

sub: sub.asm
	nasm -o $@ -f bin $<

mov: mov.asm
	nasm -o $@ -f bin $<

.PHONY : clean
clean:
	rm -f $(tests)
