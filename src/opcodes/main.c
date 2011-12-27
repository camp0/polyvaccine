#include <stdio.h>
#include "counter.h"


unsigned char *ext="\x00\x00\xaa\bb";
int len = 4;

void main() {

	int i = CO_CountSuspiciousOpcodesNew(ext,len);


}
