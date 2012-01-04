#include <stdio.h>
#include "counter.h"
#include "../detection/examples.h"
#include "../detection/examples64.h"

unsigned char *ext="\x00\x00\xaa\bb";

void main() {
	unsigned char *buffer = shellcode_64bits;
	int len = size_shellcode_64bits;

	int ret = CO_CountSuspiciousOpcodesNew(buffer,len);
	printf ("ret = %d\n",ret);

}
