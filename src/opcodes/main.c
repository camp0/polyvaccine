#include <stdio.h>
#include "counter.h"
#include "../detection/examples.h"
#include "../detection/examples64.h"

unsigned char *ext="\x00\x00\xaa\bb";

void main() {
	unsigned char *buffer = shellcode_64bits;
	int len = size_shellcode_64bits;

	CO_Init();
	printf ("1.ret = %d\n",CO_CountSuspiciousOpcodesNew(buffer,len));
	printf ("2.ret = %d\n",CO_CountSuspiciousOpcodesNew("\x90\x90\x90\x90",4));
	printf ("3.ret = %d\n",CO_CountSuspiciousOpcodesNew("\xcd\xcd\xcd\x80\x90\x90\x90\x90",8));
	printf ("4.ret = %d\n",CO_CountSuspiciousOpcodesNew("\x90\x90\x90\x90\x8b\x14\x0a\x90",8)); // 8b 14 0a es un mov indirect
	
}
