FLAGS = -g -Wall -Wextra -O3 -march=native
LDFLAGS = -lpthread

all: compile

compile:
	gcc $(FLAGS) $(LDFLAGS) lfsr.c -o lfsr

8bit: FLAGS+=-D BIT_SIZE=8
8bit: compile

64bit: FLAGS+=-D BIT_SIZE=64
64bit: compile

clean:
	rm lfsr

cachegrind:
	valgrind --tool=callgrind --dump-instr=yes --collect-jumps=yes ./lfsr
