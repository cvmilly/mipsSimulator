CC= gcc
CXX= g++ 

all: clean mips.exe

.c.o:
	$(CC) -g -O0 -c -o $@ $<
.cpp.o:
	$(CXX) -g -O0 -c -o $@ $<  -std=c++11

mips.exe: MipsSimulator.o
	$(CXX) -o mips.exe MipsSimulator.o -std=c++11

.PHONY: clean

clean:
	rm -f log.txt *.o *~ \#*\#
