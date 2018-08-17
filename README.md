# DC26 LFSR

Bruteforcer for the linear-feedback shift register puzzle present on the
official DEF CON 26 badge.

To run the 8-bit LFSR, compile in 8-bit mode:

	ross@mjolnir:/h/r/P/C/lsfr$ make 8bit
	gcc -g -Wall -Wextra -O3 -D BIT_SIZE=8 -lpthread lfsr.c -o lfsr
	ross@mjolnir:/h/r/P/C/lsfr$ ./lfsr
	Running in 8-bit mode
	Input ciphertext: 2bfc8e2b3561c04fbbc73fa43d5d96540d0aa008b30924ce47da0ec67530d3
	Starting register value: 0x0000000000000042
	Worker thread count: 20

	Tap config 0x1d: Tymkrs + Wire + Ninja wuz here!
	Test progress: 00000000000000ff/00000000000000ff (100.0%); Elapsed: 00:00 Remaining: 00:00
	All workers done!

For the 64-bit ciphertext, compile the 64bit target:

	ross@mjolnir:/h/r/P/C/lsfr$ make 64bit
	gcc -g -Wall -Wextra -O3 -D BIT_SIZE=64 -lpthread lfsr.c -o lfsr
	ross@mjolnir:/h/r/P/C/lsfr$ ./lfsr
	Running in 64-bit mode
	Input ciphertext: 9e1ce2c2f6fbfe198637e6f10b957ddd50a7874177a51e
	Starting register value: 0x8080808080808080
	Worker thread count: 20
	Tap config 0x86666666a62f3dd1: Lo44:[UkGuS 7;){3e)N"\j
	Test progress: 0000000a48f44340/ffffffffffffffff (0.0%); Elapsed: 00:30 Remaining: 211814068:36
	Tap config 0x40000000420db514: C$OiGZ4x|Ch_~h94PG*b)LR
	Test progress: 0000000aaa8a45bf/ffffffffffffffff (0.0%); Elapsed: 00:31 Remaining: 211961984:30

Be warned that the 64-bit variant will currently take approximately 25,000 years
to test all possible tap configurations.

