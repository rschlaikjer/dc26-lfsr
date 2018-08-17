all:
	gcc -Wall -Wextra -lpthread -O3 lsfr.c -o lsfr

clean:
	rm lsfr
