sources=reil_x86_translator.c libdasm.c opcode_tables.c
objects=$(sources:.c=.o)
dependencies=$(sources:.c=.d)
library=libreilx86.a

all: $(library)

# Include generated dependencies
include $(dependencies)

$(library): $(objects)
	ar -cr $@ opcode_tables.o
	ar -cr $@ libdasm.o 
	ar -cr $@ reil_x86_translator.o 

# Generate dependencies, excluding system headers.
%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$


.PHONY: clean
clean:
	rm -f $(library) $(objects) $(dependencies)
