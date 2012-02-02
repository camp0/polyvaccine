#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <assert.h>
#include "counter.h"
#include "../detection/examples.h"
#include "../detection/examples64.h"

void main() {
	int ret;

	COSU_Init();
	printf("Init test\n");

	printf("Test 1\n");
	ret = COSU_CheckSuspiciousOpcodes("\x90\x90\x90\x90",4);
	assert(ret == 0);
#ifdef __LINUX__
#if __WORDSIZE == 64
	printf("Test 2\n");
	ret = COSU_CheckSuspiciousOpcodes(shellcode_64bits,size_shellcode_64bits);
	assert(ret == 1);	
	
	printf("Test 3\n");
	ret = COSU_CheckSuspiciousOpcodes("\x00\x00\x48\x2d\x22\x00\x00\x00",8);
	assert(ret == 1);	
	
	printf("Test 4\n");
	ret = COSU_CheckSuspiciousOpcodes("\x00\x00\x90\x90\x90\x0f\x05\x00",8);
	assert(ret == 1);	
	
	printf("Test 5\n");
	ret = COSU_CheckSuspiciousOpcodes(helloworld,size_helloworld);
	assert(ret == 1);	
	
	printf("Test 6\n");
	ret = COSU_CheckSuspiciousOpcodes(add_root_user_64bits,size_add_root_user_64bits);
	assert(ret == 1);	
#else
	ret = COSU_CheckSuspiciousOpcodes("\xcd\xcd\xcd\x80\x90\x90\x90\x90",8);
	assert(ret == 1);
	
	ret = COSU_CheckSuspiciousOpcodes("\x90\x90\x90\x90\x8b\x0b\x0a\x90",8); // 8b 0b es un mov indirect
	assert(ret == 1);
	
	ret = COSU_CheckSuspiciousOpcodes("\x90\x90\x90\x90\x8b\x44\x0d\x90",8); // 8b 14 0a es un mov indirect
	assert(ret == 1);	

	ret = COSU_CheckSuspiciousOpcodes(admmutate_1_32bits,size_admmutate_1_32bits);
	assert(ret == 1);

	ret = COSU_CheckSuspiciousOpcodes(fnstenv_1_32bits,size_fnstenv_1_32bits);
	assert(ret == 1);

#endif
#endif
	COSU_Stats();
	COSU_Destroy();
	printf("Tests done\n");
}
