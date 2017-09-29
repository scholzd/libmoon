#define _GNU_SOURCE 1

#include <inttypes.h>
#include <stdio.h>
#include <sched.h>

void wait_cycles(uint32_t wait ) {
	
		asm volatile("mov %0, %%ecx\n\t"
				"inc %%ecx\n\t"
				"1: dec %%ecx\n\t"
				"cmp $0, %%ecx\n\t"
				"jnz 1b"::"r" (wait));

}
