# Tests makefile

tests = add sub

all: $(tests)

add: add.asm
	nasm -o $@ -f bin $<

sub: sub.asm
	nasm -o $@ -f bin $<

.PHONY : clean
clean:
	rm -f $(tests)
