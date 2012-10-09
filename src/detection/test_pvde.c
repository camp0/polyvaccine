#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "sandbox.h"
#include "examples64.h"
#include <assert.h>

static void test01(void) {
	/* Two nop instructions and syscall exit 1 */
	unsigned char *buffer = "\x90\x90" "\xbb\x01\x00\x00\x00" "\xb8\x3c\x00\x00\x00" "\xbf\x01\x00\x00\x00" "\x0f\x05";
	int size = 19;
	ST_Sandbox *sand = NULL;
	int ret;

	printf("***************** testing %s ******************\n",__FUNCTION__);

	sand = SABX_Init();

	ret = SABX_AnalyzeSegmentMemory(sand,buffer,size,NULL);

	assert(sand->total_shellcodes == 1);
	assert(sand->total_executed == 1);
	assert(sand->ctx->total_segs_by_child == 0);
	assert(sand->ctx->jump_offset == 1);	
	assert(sand->ctx->total_forks == 1);	

	SABX_Destroy(sand);

	return;
}

static void test02(void) {
	/* one nop and one SIGSEGV with a syscall exit 1 */
        unsigned char *buffer = "\x90\x00" "\xbb\x01\x00\x00\x00" "\xb8\x3c\x00\x00\x00" "\xbf\x01\x00\x00\x00" "\x0f\x05";
        int size = 19;
        ST_Sandbox *sand = NULL;
        int ret;
	
	printf("***************** testing %s ******************\n",__FUNCTION__);

        sand = SABX_Init();

        ret = SABX_AnalyzeSegmentMemory(sand,buffer,size,NULL);

        assert(sand->total_shellcodes == 1);
        assert(sand->total_executed == 1);
	assert(sand->ctx->total_segs_by_child == 1);	
	assert(sand->ctx->jump_offset == 2);
	assert(sand->ctx->total_forks == 1);	

        SABX_Destroy(sand);
	
        return;
}

static void test03(void) {
        unsigned char *buffer = "\x90\x90\x90\x90\x90\x90";
        int size = 6;
        ST_Sandbox *sand = NULL;
        int ret;

	printf("***************** testing %s ******************\n",__FUNCTION__);

        sand = SABX_Init();

        ret = SABX_AnalyzeSegmentMemory(sand,buffer,size,NULL);

        assert(sand->total_shellcodes == 0);
        assert(sand->total_executed == 1);
        assert(sand->ctx->total_segs_by_child == 0);
	assert(sand->ctx->jump_offset == 6);
	assert(sand->ctx->total_forks == 5);	
        SABX_Destroy(sand);

        return;
}

static void test04(void) {
        unsigned char *buffer = 
		"GET / HTTP/1.1"
		"Accept: */*"
		"Accept-Language: es"
		"Host: www.pepe.org"
	;
        ST_Sandbox *sand = NULL;
        int ret;

	printf("***************** testing %s ******************\n",__FUNCTION__);

        sand = SABX_Init();

        ret = SABX_AnalyzeSegmentMemory(sand,buffer,strlen(buffer),NULL);

        assert(sand->total_shellcodes == 0);
        assert(sand->total_executed == 1);
        assert(sand->ctx->total_segs_by_child == 48);
        assert(sand->ctx->jump_offset == 62);
	
        SABX_Destroy(sand);

        return;
}

static void test05(void) {
	/* Generates 5 SIGSEGV on the child */
        unsigned char *buffer =
		"\x00\x00\x00\x00\x00"
		"\xbb\x01\x00\x00\x00" "\xb8\x3c\x00\x00\x00" "\xbf\x01\x00\x00\x00" "\x0f\x05"
        ;
        ST_Sandbox *sand = NULL;
        int ret,size;

	printf("***************** testing %s ******************\n",__FUNCTION__);

	size = 17 /* opcodes */ + 5;
        sand = SABX_Init();

        ret = SABX_AnalyzeSegmentMemory(sand,buffer,size,NULL);

        assert(sand->total_shellcodes == 1);
        assert(sand->total_executed == 1);
        assert(sand->ctx->total_segs_by_child == 4);
        assert(sand->ctx->jump_offset == 5);

        SABX_Destroy(sand);

        return;
}

static void test06(void) {
        /* Generates 5 SIGSEGV on the child */
        unsigned char *buffer =
                "GET / HTTP/1.1"
                "\xbb\x01\x00\x00\x00" "\xb8\x3c\x00\x00\x00" "\xbf\x01\x00\x00\x00" "\x0f\x05"
        ;
        ST_Sandbox *sand = NULL;
        int ret,size;

	printf("***************** testing %s ******************\n",__FUNCTION__);

        size = 17 /* opcodes */ + 14;
        sand = SABX_Init();

        ret = SABX_AnalyzeSegmentMemory(sand,buffer,size,NULL);

        assert(sand->total_shellcodes == 1);
        assert(sand->total_executed == 1);
        assert(sand->ctx->total_segs_by_child == 8);
        assert(sand->ctx->jump_offset == 14);
	assert(sand->ctx->total_forks == 6);	

        SABX_Destroy(sand);

        return;
}


int main(int argc, char *argv[])
{

	test01();
	sleep(1);
	test02();
	sleep(1);
	test03();
	sleep(1);
	test04();
	sleep(1); 
	test05();
	sleep(1); 
	test06();
	return 0;	
}

