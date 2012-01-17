export CC=clang
export CFLAGS=-std=gnu99 -Wall -Wextra -Wno-missing-field-initializers -g -O0
LDFLAGS=-Lx86 -lreilx86

sources=reil_translator.c reil.c 
objects=$(sources:.c=.o)
dependencies=$(sources:.c=.d)
program=reil_translator

submodules=tests
translators=x86

all: $(program) $(submodules) 

# Include generated dependencies
include $(dependencies)

$(program): $(objects) $(translators)
	$(CC) -o $(program) $(objects) $(LDFLAGS) 

.PHONY : translators $(translators) 
translators: $(translators)

$(translators):
	$(MAKE) -C $@

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
	rm -f $(objects) $(dependencies) $(program)
	@for translator in $(translators); do \
		$(MAKE) -C $$translator clean; \
	done
	@for submodule in $(submodules); do \
		$(MAKE) -C $$submodule clean; \
	done
