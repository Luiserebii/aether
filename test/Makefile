CXX_INCLUDE_FLAGS=-I./lib/Catch2-2.13.6/include  -I../build/include
# LD_LIBRARY_PATH=.. ./$(PRG_OUT)
CXXFLAGS= -g3 -Wall -Wextra -Wvla $(CXX_INCLUDE_FLAGS)
CXX=g++
LINK_FLAGS=-L.. -l$(LIB) -lsecp256k1 -lgmp

LIB=aether
LIB_NAME=lib$(LIB).so

PRG_OUT=test

test: compile run

memory: compile
	LD_LIBRARY_PATH=~/github/aether/ valgrind ./$(PRG_OUT)

run:
	LD_LIBRARY_PATH=~/github/aether/ ./$(PRG_OUT)

compile: aether
	$(CXX) $(CXXFLAGS) $(C_INCLUDE_FLAGS) ./src/*.cpp $(LINK_FLAGS) -o $(PRG_OUT)

aether:
	cd .. && make

clean: 
	rm $(PRG_OUT) && cd .. && make clean
