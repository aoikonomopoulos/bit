modules = il

.PHONY: modules $(modules)

all: modules
modules: $(modules)

$(modules):
	$(MAKE) -C $@

.PHONY: clean
clean:
	@for module in $(modules); do \
		$(MAKE) -C $$module clean; \
	done
