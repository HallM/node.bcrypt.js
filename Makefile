TESTS = test/*.js

all: test

build: clean configure compile
	ln -sf build/default/bcrypt_lib.node bcrypt_lib.node

configure:
	node-waf configure

compile:
	node-waf build

test: build
	@./node_modules/nodeunit/bin/nodeunit \
		$(TESTS)

clean:
	rm -Rf bcrypt_lib.node
	rm -Rf build


.PHONY: clean test build