#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <assert.h>
#include "counter.h"
#include "../detection/examples.h"
#include "../detection/examples64.h"

unsigned char *ext="\x00\x00\xaa\bb";

void main() {
	unsigned char *buffer = shellcode_64bits;
	int len = size_shellcode_64bits;
	int ret;

	printf("Init test\n");
	COSU_Init();

	ret = COSU_CheckSuspiciousOpcodes(buffer,len);
	assert(ret == 1);	

	ret = COSU_CheckSuspiciousOpcodes("\x90\x90\x90\x90",4);
	assert(ret == 0);

	ret = COSU_CheckSuspiciousOpcodes("\xcd\xcd\xcd\x80\x90\x90\x90\x90",8);
	assert(ret == 1);

	ret = COSU_CheckSuspiciousOpcodes("\x90\x90\x90\x90\x8b\x0b\x0a\x90",8); // 8b 0b es un mov indirect
	assert(ret == 1);

	ret = COSU_CheckSuspiciousOpcodes("\x90\x90\x90\x90\x8b\x44\x0d\x90",8); // 8b 14 0a es un mov indirect
	assert(ret == 1);	
	printf("Tets done\n");
}
