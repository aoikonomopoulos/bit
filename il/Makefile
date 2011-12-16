CC=gcc
CFLAGS=-Wall -g

sources=reil_translator.c libdasm.c reil.c reil_x86_translator.c
objects=$(sources:.c=.o)
program=reil_translator

all: $(program) tests

include $(sources:.c=.d)

$(program): $(objects)
	$(CC) $(CFLAGS) $(objects) -o $(program)

.PHONY : tests
tests:
	$(MAKE) -C tests

# Generate dependencies, excluding system headers.
%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$


.PHONY : clean
clean:
	rm -f $(objects) $(program)
	$(MAKE) -C tests clean
