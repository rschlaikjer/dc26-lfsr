all:
	gcc -g -Wall -Wextra -lpthread -O3 lsfr.c -o lsfr

clean:
	rm lsfr
