CXX_INCLUDE_FLAGS=-I./lib/Catch2-2.13.6/include -I../lib/C-STL-master/include -I../include
CXXFLAGS= -g3 -Wall -Wextra -Wvla $(CXX_INCLUDE_FLAGS)
CXX=g++
LINK_FLAGS=-L.. -l$(LIB)

LIB=aether
LIB_NAME=lib$(LIB).so

PRG_OUT=test

test: compile run

run:
	LD_LIBRARY_PATH=~/github/aether/ ./$(PRG_OUT)

compile: aether
	$(CXX) $(CXXFLAGS) $(C_INCLUDE_FLAGS) ./src/*.cpp $(LINK_FLAGS) -o $(PRG_OUT)

aether:
	cd .. && make

clean: 
	rm $(PRG_OUT) && cd .. && make clean
