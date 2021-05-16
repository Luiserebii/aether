C_INCLUDE_FLAGS=-I./lib/ethash-0.6.0/include -I./lib/C-STL-master/include
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

compile: 
	$(CC) $(CFLAGS) ./src/**/*.c $(DEP_SRC) $(OBJECT_DEPS) $(LINK_FLAGS) -o $(LIB_OUT_NAME)

static:

install: 
	cp $(LIB_OUT_NAME) /usr/lib
	mkdir -p /usr/include/aether
	cp -r ./include/* /usr/include/aether

uninstall:
	rm /usr/lib/$(LIB_OUT_NAME)
	rm -rf /usr/include/aether

clean: 
	rm $(LIB_OUT_NAME)
