CC=gcc
CFLAGS=-Wall -g

sources=reil_translator.c libdasm.c reil.c reil_x86_translator.c
objects=$(sources:.c=.o)
program=reil_translator

submodules=tests

all: $(program) $(submodules) 

# Include generated dependencies
include $(sources:.c=.d)

$(program): $(objects)
	$(CC) $(CFLAGS) $(objects) -o $(program)

.PHONY : submodules $(submodules) 
submodules: $(submodules)

$(submodules):
	$(MAKE) -C $@

# Generate dependencies, excluding system headers.
%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$


.PHONY: clean
clean:
	rm -f $(objects) $(sources:.c=.d) $(program)
	@for submodule in $(submodules); do \
		$(MAKE) -C $$submodule clean; \
	done
