#include <stdio.h>
#include <assert.h>
#include "flowpool.h"
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

static testmatrix tests[] = {
	{ .desc = "test 01", .function = test01 },
	{ .desc = "test 02", .function = test02 },
	{ .desc = "test 03", .function = test03 },
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
