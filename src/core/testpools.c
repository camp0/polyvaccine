#include <stdio.h>
#include <assert.h>
#include "memorypool.h"
#include "flowpool.h"
#include "userpool.h"
#include "user.h"
#include "pool.h"

struct testmatrix{
	char *desc;
	void (*function)(void);
};
typedef struct testmatrix testmatrix;

void test03(void) {
	ST_Pool *pool= NULL;
	register int i;

	pool = POOL_Init();

	for (i = 0;i<10;i++){
		char *ptr = malloc(1024);
		POOL_AddItem(pool,ptr);
	}
	for (i = 0;i<10;i++){
		char *ptr = POOL_GetItem(pool);
		free(ptr);
		ptr = NULL;	
	} 
	POOL_Destroy(pool);
	return;
}

void test02(void){
	ST_FlowPool *fpool = NULL;
	ST_GenericFlow *flow = NULL;

        fpool = FLPO_Init();

        assert( flow == NULL);
        assert( FLPO_GetNumberFlows(fpool) != 0);
        FLPO_Destroy(fpool);
	
	return;
}

void test01(void){
	ST_FlowPool *fpool = NULL;
	ST_GenericFlow *flow = NULL;

	fpool = FLPO_Init();

	int value = FLPO_GetNumberFlows(fpool);
	FLPO_DecrementFlowPool(fpool,value);
	flow = FLPO_GetFlow(fpool);	

	assert( flow == NULL);
	assert( FLPO_GetNumberFlows(fpool) == 0); 
	FLPO_Destroy(fpool);
	return;
}

void test04(void){
	ST_UserPool *upool = NULL;
	ST_User *user1,*user2;

	upool = USPO_Init();

	user1 = USPO_GetUser(upool);
	USPO_AddUser(upool,user1);
	user2 = USPO_GetUser(upool);

	assert ( user1 == user2);
	
	USPO_Destroy(upool);
	return;
}	

void test05(void){
        ST_UserPool *upool = NULL;
        ST_User *user;
	register int i;

        upool = USPO_Init();

	USPO_DecrementUserPool(upool,10000000);
        user = USPO_GetUser(upool);
	assert( user == NULL);
	
	USPO_IncrementUserPool(upool,20000);

        USPO_Destroy(upool);
        return;
}

void test06(void){
        ST_MemoryPool *mpool = NULL;
        ST_MemorySegment *mem = NULL;	

	mpool = MEPO_Init();

	mem = MEPO_GetMemorySegment(mpool);

	MESG_AppendPayload(mem,"hola",4);

	assert(mem->real_size == 512);	
	assert(mem->virtual_size == 4);
	
	MESG_AppendPayload(mem,"holaaa",6);
	assert(mem->virtual_size == 10);
	assert(mem->real_size == 512);	

	MESG_Reset(mem);
	assert(mem->virtual_size == 0);
	assert(mem->real_size == 512);	

	MEPO_AddMemorySegment(mpool,mem);

	mem = MESG_InitWithSize(16);
	assert(mem->virtual_size == 0);
	assert(mem->real_size == 16);	

	MESG_AppendPayload(mem,"1234567890",10);
	MESG_AppendPayload(mem,"1234567890",10);
	MESG_AppendPayload(mem,"1234567890",10);
	assert(mem->virtual_size == 30);
	assert(mem->real_size == 30);	


	MESG_Destroy(mem);
	MEPO_Destroy(mpool);

	//assert( mpool == NULL);

	return;
}

static testmatrix tests[] = {
	{ .desc = "test 01", .function = test01 },
	{ .desc = "test 02", .function = test02 },
	{ .desc = "test 03", .function = test03 },
	{ .desc = "test 04 user pools", .function = test04 },
	{ .desc = "test 05 user pools", .function = test05 },
	{ .desc = "test 06 memory pools", .function = test06 },
	{}
};	

void main(int argc, char **argv) {
	register int i;

	i = 0;
	while(tests[i].desc!=  NULL){
		printf("Executing %s\n",tests[i].desc);
		tests[i].function();
		i++;
	}

	return;
}
