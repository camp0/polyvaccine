#include <stdio.h>
#include <errno.h>
#include "sandbox.h"
#include "examples64.h"
#include <assert.h>

static void test01(void) {
	unsigned char *buffer = "\x90\x90" "\xbb\x01\x00\x00\x00" "\xb8\x3c\x00\x00\x00" "\xbf\x01\x00\x00\x00" "\x0f\x05";
	int size = 19;
	ST_Sandbox *sand = NULL;
	int ret;

	printf("testing 01\n");

	sand = SABX_Init();

	ret = SABX_AnalyzeSegmentMemory(sand,buffer,size,NULL);

	assert(sand->total_shellcodes == 1);
	assert(sand->total_executed == 1);
	assert(sand->ctx->total_segs_by_child == 0);
	assert(sand->ctx->jump_offset == 1);	

	SABX_Destroy(sand);

	return;
}

static void test02(void) {
        unsigned char *buffer = "\x90\x00" "\xbb\x01\x00\x00\x00" "\xb8\x3c\x00\x00\x00" "\xbf\x01\x00\x00\x00" "\x0f\x05";
        int size = 19;
        ST_Sandbox *sand = NULL;
        int ret;
	
	printf("testing 02\n");

        sand = SABX_Init();

        ret = SABX_AnalyzeSegmentMemory(sand,buffer,size,NULL);

        assert(sand->total_shellcodes == 1);
        assert(sand->total_executed == 1);
	assert(sand->ctx->total_segs_by_child == 1);	
	assert(sand->ctx->jump_offset ==2);

        SABX_Destroy(sand);
	
        return;
}

static void test03(void) {
        unsigned char *buffer = "\x90\x90\x90\x90\x90\x90";
        int size = 6;
        ST_Sandbox *sand = NULL;
        int ret;

        printf("testing 03\n");

        sand = SABX_Init();

        ret = SABX_AnalyzeSegmentMemory(sand,buffer,size,NULL);

        assert(sand->total_shellcodes == 0);
        assert(sand->total_executed == 1);
        assert(sand->ctx->total_segs_by_child == 0);
	assert(sand->ctx->jump_offset == 0);
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

        printf("testing 04\n");

        sand = SABX_Init();

        ret = SABX_AnalyzeSegmentMemory(sand,buffer,strlen(buffer),NULL);
	printf("len=%d\n",strlen(buffer));
        assert(sand->total_shellcodes == 0);
        assert(sand->total_executed == 1);
        assert(sand->ctx->total_segs_by_child == 61);
        assert(sand->ctx->jump_offset == 0);
	printf("jump_offset=%d\n",sand->ctx->jump_offset);
        SABX_Destroy(sand);

        return;
}

int main(int argc, char *argv[])
{
	test01();
	test02();
	test03();
//	test04();
	return 0;	
}

