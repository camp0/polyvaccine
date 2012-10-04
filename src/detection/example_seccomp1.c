#include <stdio.h>
#include <errno.h>
#include "sandbox.h"
#include "examples64.h"


/*
   0:	90                   	nop
   1:	90                   	nop
   2:	bb 01 00 00 00       	mov    $0x1,%ebx
   7:	b8 3c 00 00 00       	mov    $0x3c,%eax
   c:	bf 01 00 00 00       	mov    $0x1,%edi
  11:	0f 05 
*/

//static unsigned char *buffer_1 = "\x90\x90" "\xbb\x01\x00\x00\x00" "\xb8\x3c\x00\x00\x00" "\xbf\x01\x00\x00\x00" "\x0f\x05";
static unsigned char *buffer_1 = "\x90\x00" "\xbb\x01\x00\x00\x00" "\xb8\x3c\x00\x00\x00" "\xbf\x01\x00\x00\x00" "\x0f\x05";

int main(int argc, char *argv[])
{
	int ret;
	struct stat st;
	int status;
	pid_t pid;
	siginfo_t sig;
	unsigned char *buffer = buffer_1;
	int size = 19;
	ST_Sandbox *sand = NULL;
	int magic_token = 100;

	sand = SABX_Init();


	ret = SABX_AnalyzeSegmentMemory(sand,buffer,size,NULL);

	SABX_Statistics(sand);
	SABX_Destroy(sand);
	return 0;	
}

