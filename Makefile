C_INCLUDE_FLAGS=-I./lib/ethash-0.6.0/include -I./lib/C-STL-master/include -I./include/ -I./src/include/
LINK_FLAGS=-lsecp256k1 -lm
CFLAGS= -g3 -Wall -Wextra -Wvla -shared -fPIC $(C_INCLUDE_FLAGS)
#-Wl,-soname,$(LIB_OUT_NAME).$(LIB_VER)
CC=cc

ETHASH_SRC=./lib/ethash-0.6.0/lib/keccak/keccak.c
CSTL_SRC=./lib/C-STL-master/src/memory.c
DEP_SRC=$(ETHASH_SRC) $(CSTL_SRC)

LIB_VER=0.0.1
LIB_OUT=aether
LIB_OUT_NAME=lib$(LIB_OUT).so

.PHONY: compile
compile: setup
	$(CC) $(CFLAGS) ./src/*.c ./src/**/*.c $(DEP_SRC) $(LINK_FLAGS) -o $(LIB_OUT_NAME)

.PHONY: setup
setup:
	mkdir -p ./build
	mkdir -p ./include/aether/cstl
	cp ./lib/C-STL-master/include/cstl/vector.h ./include/aether/cstl

.PHONY: lint
lint:
	./scripts/lint.sh

.PHONY: install
install: 
	cp $(LIB_OUT_NAME) /usr/lib
	cp -r ./include/* /usr/include/

.PHONY: uninstall
uninstall:
	rm /usr/lib/$(LIB_OUT_NAME)
	rm -rf /usr/include/aether

.PHONY: clean
clean: 
	rm $(LIB_OUT_NAME) && rm -rf build
