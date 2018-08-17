FLAGS = -g -Wall -Wextra -O3
LDFLAGS = -lpthread

all:
	gcc $(FLAGS) $(LDFLAGS) lfsr.c -o lfsr

clean:
	rm lfsr

cachegrind:
	valgrind --tool=callgrind --dump-instr=yes --collect-jumps=yes ./lfsr
