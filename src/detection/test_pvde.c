#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "sandbox.h"
#include "examples64.h"
#include <assert.h>

int show_statistics = 0;

static void test01(void) {
	/* Two nop instructions and syscall exit 1 */
	unsigned char *buffer = "\x90\x90" "\xbb\x01\x00\x00\x00" "\xb8\x3c\x00\x00\x00" "\xbf\x01\x00\x00\x00" "\x0f\x05";
	int size = 19;
	ST_Sandbox *sand = NULL;
	int ret;

	printf("***************** testing %s ******************\n",__FUNCTION__);

	sand = SABX_Init();

	ret = SABX_AnalyzeSegmentMemory(sand,buffer,size,NULL);
	if(show_statistics)SABX_Statistics(sand);

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
	if(show_statistics)SABX_Statistics(sand);

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
	if(show_statistics)SABX_Statistics(sand);

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
	if(show_statistics)SABX_Statistics(sand);

        assert(sand->total_shellcodes == 0);
        assert(sand->total_executed == 1);
        assert(sand->ctx->total_segs_by_child >= 46 && sand->ctx->total_segs_by_child <= 48);
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
	if(show_statistics)SABX_Statistics(sand);

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

	if(show_statistics)SABX_Statistics(sand);
        assert(sand->total_shellcodes == 1);
        assert(sand->total_executed == 1);
        assert(sand->ctx->total_segs_by_child == 8);
        assert(sand->ctx->jump_offset == 14);
	assert(sand->ctx->total_forks == 6);	

        SABX_Destroy(sand);

        return;
}

static void test07(void) {
        /* Generates 5 SIGSEGV on the child */
        unsigned char *buffer =
		"GET /gestor/ficheros/banner0.swf HTTP/1.1"
		"Accept: */*"
		"x-flash-version: 8,0,22,0"
		"UA-CPU: x86"
		"Accept-Encoding: gzip, deflate"
		"If-Modified-Since: Tue, 09 Jan 2007 13:09:52 GMT"
		"User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322)"
		"Host: black.hole.somedomain.com"
		"Connection: Keep-Alive"
        ;
        ST_Sandbox *sand = NULL;
        int ret,size;

        printf("***************** testing %s ******************\n",__FUNCTION__);

        size = strlen(buffer);
        sand = SABX_Init();

        ret = SABX_AnalyzeSegmentMemory(sand,buffer,size,NULL);

	if(show_statistics)SABX_Statistics(sand);

        assert(sand->total_shellcodes == 0);
        assert(sand->total_executed == 1);
        assert(sand->ctx->total_segs_by_child >= 258 && sand->ctx->total_segs_by_child < 300);
        assert(sand->ctx->total_forks >= 36);
        SABX_Destroy(sand);

        return;
}

static void test08(void) {
        unsigned char *buffer =
                "GET /gestor/ficheros/banner0.swf HTTP/1.1"
                "Accept: */*"
                "x-flash-version: 8,0,22,0"
                "UA-CPU: x86"
		/* open("/etc/passwd", O_WRONLY|O_CREAT|O_APPEND, 01204) */
        	"\x48\xbb\xff\xff\xff\xff\xff\x73\x77\x64"       /* mov    $0x647773ffffffffff,%rbx */
        	"\x48\xc1\xeb\x28"                               /* shr    $0x28,%rbx */
        	"\x53"                                           /* push   %rbx */
        	"\x48\xbb\x2f\x65\x74\x63\x2f\x70\x61\x73"       /* mov    $0x7361702f6374652f,%rbx */
        	"\x53"                                           /* push   %rbx */
        	"\x48\x89\xe7"                                   /* mov    %rsp,%rdi */
        	"\x66\xbe\x41\x04"                               /* mov    $0x441,%si */
        	"\x66\xba\x84\x02"                               /* mov    $0x284,%dx */
        	"\x48\x31\xc0"                                   /* xor    %rax,%rax */
        	"\xb0\x02"                                       /* mov    $0x2,%al */
        	"\x0f\x05"                                       /* syscall */
                //"Accept-Encoding: gzip, deflate"
                //"If-Modified-Since: Tue, 09 Jan 2007 13:09:52 GMT"
                //"User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322)"
                //"Host: black.hole.somedomain.com"
                //"Connection: Keep-Alive"
        ;
        ST_Sandbox *sand = NULL;
        int ret,size;

        printf("***************** testing %s ******************\n",__FUNCTION__);

        size = 88 + 54;
        sand = SABX_Init();

        ret = SABX_AnalyzeSegmentMemory(sand,buffer,size,NULL);
	if(show_statistics)SABX_Statistics(sand);

        assert(sand->total_shellcodes == 1);
        assert(sand->total_executed == 1);
        assert(sand->ctx->jump_offset == 1);
        assert(sand->ctx->total_forks == 1);
        SABX_Destroy(sand);

        return;
}


int main(int argc, char *argv[])
{

	if(argc>1)show_statistics = 1;

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
	sleep(1); 
	test07();
	sleep(1);
	test08();
	return 0;	
}

