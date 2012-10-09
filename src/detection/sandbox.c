/* 
 * Polyvaccine a Polymorphic exploit detection engine.
 *                                                              
 * Copyright (C) 2009  Luis Campo Giralte 
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2009 
 *
 */

#include "sandbox.h"

#define POLYLOG_CATEGORY_NAME POLYVACCINE_DETECTION_INTERFACE ".sandbox"
#include "log.h"

static ST_Sandbox *sandbox = NULL;
static ST_SharedContext *shctx = NULL; 
int got_child_signal;

/**
 * SABX_Init - Creates a ST_Sandox struct 
 *
 * @return ST_Sandbox 
 *
 */
ST_Sandbox *SABX_Init() {
	ST_Sandbox *sx = g_new0(ST_Sandbox,1);

	srand(time(NULL));

	sx->total_executed = 0;
	sx->total_shellcodes = 0;
	sx->debug_level = 0;
    
	/* Creates a new shared context */
        shctx = COXT_GetContext();

        sx->ctx = shctx;
	POLG_Init();	
	sandbox = sx; // this is ugly :( TODO	
	return sx;
}

/**
 * SABX_Destroy - Free a ST_Sandox struct 
 *
 * @param sx 
 *
 */
void SABX_Destroy(ST_Sandbox *sx){

	POLG_Destroy();
	COXT_FreeContext(sx->ctx);
	sx->seg = NULL;
	sx->ctx = NULL;
	g_free(sx);
	sx = NULL;
	
	return;	
}

/**
 * SABX_Statistics - Show the statistics of a ST_Sandox struct
 *
 * @param sx
 *
 */
void SABX_Statistics(ST_Sandbox *sx) {

	printf("Sandox statistics\n");
	printf("\ttotal executed %d, total shellcodes %d\n",sx->total_executed,sx->total_shellcodes);
	COXT_Printf(shctx);	

	return;

}

/**
 * __SABX_InitSandbox - Initialize the seccomp rules on the kernel via libseccomp 
 *
 * @param magic_token 
 *
 * @return status
 */
int __SABX_InitSandbox(int magic_token) {
        int ret = 0;

        ret = seccomp_init(SCMP_ACT_KILL);
        if(ret == -1) return -2;

        /* the exit syscall */
        ret = seccomp_rule_add_exact(SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 1,SCMP_A0(SCMP_CMP_EQ,magic_token));
        if (ret != 0)return ret;

        ret = seccomp_rule_add_exact(SCMP_ACT_ALLOW, SCMP_SYS(exit), 1,SCMP_A0(SCMP_CMP_EQ,magic_token));
        if (ret != 0)return ret;

        ret = seccomp_rule_add_exact(SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
        if (ret != 0)return ret;

        ret = seccomp_rule_add_exact(SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
        if (ret != 0) return ret;

        /* Allow messages to stdout */
        ret = seccomp_rule_add_exact(SCMP_ACT_ALLOW, SCMP_SYS(open),1 ,SCMP_A0(SCMP_CMP_EQ, STDOUT_FILENO));
        if (ret != 0) return ret;

        ret = seccomp_rule_add_exact(SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
        if (ret != 0) return ret;

	/* The log subsystem log4c uses this syscall */
        ret = seccomp_rule_add_exact(SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);
        if (ret != 0) return ret;

        /* some libcs caches the values
        ret = seccomp_rule_add_exact(SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
        if(ret!= 0) return ret;
        */

        ret = seccomp_load();
        return ret;
}


#define POLYLOG_CATEGORY_NAME POLYVACCINE_DETECTION_INTERFACE ".sandbox.child"

/**
 * __SABX_SigSegvHandler - Callback for manage the SIGSEGV signal and others on the child process.
 *      Most of the request executed dont have shellcodes but generates lost CPU cycles.
 *      By reusing the same child process and we increase the performance of the pvde, due to
 *      the pvde reduce the number of forks operations.
 *
 * @param sig
 * @param info
 * @param data
 *
 */
void __SABX_SigSegvHandler(int sig, siginfo_t *info, void *data) {
	ST_ExecutableSegment *seg = sandbox->seg;

#ifdef DEBUG
        LOG(POLYLOG_PRIORITY_DEBUG,
                "child(%d) receives signal %d on jump offset %d",getpid(),sig,shctx->jump_address);
#endif
        LOG(POLYLOG_PRIORITY_INFO,
		"signal(%d)jump(%d)size(%d)token(%d)",
		sig,shctx->jump_offset,shctx->max_jump_offset,shctx->magic_token);

        if((shctx->jump_offset>=shctx->max_jump_offset)||(shctx->jump_offset < 0)) {
#ifdef DEBUG
                LOG(POLYLOG_PRIORITY_DEBUG,
                        "child(%d) Overflow exit on virtualeip=%d size=%d",getpid(),
                        ctx->virtualeip ,ctx->size);
#endif
                shctx->jump_offset = shctx->max_jump_offset;
                exit(shctx->magic_token);
        }
	shctx->jump_offset++;
	shctx->total_segs_by_child++;

	EXSG_SetJumpOffsetOnExecutableSegment(seg,shctx->jump_offset);

	EXSG_ExecuteExecutableSegment(seg);

        LOG(POLYLOG_PRIORITY_INFO,
               "exiting segment on sandbox token(%d)jump(%d)size(%d)",shctx->magic_token,shctx->jump_offset,shctx->max_jump_offset);
        exit(shctx->magic_token);
        //exit(0);
}


/**
 * __SABX_SetSignalHandlers - Sets the signals for the child process 
 *
 *
 */
void __SABX_SetSignalHandlers(void) {
	struct sigaction sa;

        sigemptyset (&sa.sa_mask);
        sa.sa_sigaction = (void *)__SABX_SigSegvHandler;
        sa.sa_flags = SA_RESTART | SA_NODEFER; // el flag SA_NODEFER es el que hace que se itere

        sigaction(SIGSEGV, &sa, NULL); // Invalid memory Reference

	return;
}

/**
 * __SABX_SigUsrSignalHandler - Sets the SIGUSR1 handler for syncronize parent and child 
 *
 * @param signal
 *
 */
void __SABX_SigUsrSignalHandler(int signal) {
        got_child_signal = 1;
        return;
}

/**
 * __SABX_Executor - Child executes a sx with a magic token variable 
 *
 * @param sg
 * @param magic_token
 *
 */
void __SABX_Executor(ST_ExecutableSegment *sg) {
        int ret;

	shctx->child_pid = getpid();
	shctx->parent_pid = getppid();
	shctx->total_forks++;

	__SABX_SetSignalHandlers();       
	kill(getppid(), SIGUSR1);
	while(!got_child_signal);

        LOG(POLYLOG_PRIORITY_INFO,
               "Executing segment on sandbox token(%d)jump(%d)",shctx->magic_token,shctx->jump_offset);

        ret = __SABX_InitSandbox(shctx->magic_token);

#ifdef DEBUG
	EXSG_PrintExecutableSegment(sg);
#endif

        EXSG_ExecuteExecutableSegment(sg);

        LOG(POLYLOG_PRIORITY_INFO,
               "Escape from sandbox token(%d)",shctx->magic_token);
        exit(shctx->magic_token);
}

#define POLYLOG_CATEGORY_NAME POLYVACCINE_DETECTION_INTERFACE ".sandbox"

/**
 * __SABX_WaitForExecution - The sandbox waits child execution 
 *
 * @param pid 
 *
 * @return status
 */
int __SABX_WaitForExecution(pid_t pid) {
	int status;
	siginfo_t sig;
	int ret = 0;

        status = waitid(P_PID,pid,&sig,WEXITED|WSTOPPED|WCONTINUED|WNOWAIT);

        switch(sig.si_code){
		case CLD_STOPPED:
			//printf("child stoped\n");
			break;
		case CLD_TRAPPED:
			//printf("child trapped\n");
			break;
		case CLD_DUMPED:
			//printf("child dumpede\n");
			break;
		case CLD_CONTINUED:
			//printf("child continue\n");
			break;
                case CLD_EXITED:
                        //printf("child exists correct\n");
			ret = 2;
                        break;
                case CLD_KILLED:
			if(sig.si_status == SIGSYS) {
                        	//printf("child killed by seccomp\n");
				ret = 1;
				break;
			}
			if(sig.si_status == SIGILL) { // the process executes an illegal isntruction
				//printf("child killed by SIGILL\n");
				ret = 2;
				break;
			}
			if(sig.si_status == SIGSEGV) {
				ret = 2;
				break;
			}
			printf("child killed by other reason\n");
                        break;
        }
        LOG(POLYLOG_PRIORITY_INFO,
                "Sandbox receives status(%d)pid(%d)code(%d)status(%d)killseccomp(%d)",
		status,sig.si_pid,sig.si_code,sig.si_status,ret);

	return ret;
}


#define POLYLOG_CATEGORY_NAME POLYVACCINE_DETECTION_INTERFACE ".sandbox"

/**
 * SABX_AnalyzeSegmentMemory - Main function that test if a buffer contains a shellcode.
 *
 * @param buffer
 * @param size
 * @param t_off
 *
 */
int SABX_AnalyzeSegmentMemory(ST_Sandbox *sx,char *buffer, int size, ST_TrustOffsets *t_off) {
	int ret = 0;
	register int i;
	pid_t pid;
	int status;
	
	got_child_signal = 0;
	signal(SIGUSR1, __SABX_SigUsrSignalHandler);

	/* Reset shared context for this request */
	COXT_ResetContext(sx->ctx);

	shctx->magic_token = rand(); 
	shctx->jump_offset = 1;
	shctx->max_jump_offset = size;

        LOG(POLYLOG_PRIORITY_INFO,
                "Analyzing segment on sandbox token(%d)size(%d)",shctx->magic_token,size);

	/* Creates a new execution segment for the suspicious request */
	sx->seg = EXSG_InitExecutableSegment();
        EXSG_PrepareExecutableSegment(sx->seg,buffer,size);

	/* Check all the posible offsets of the request */
	do {
		/* Generate a magic token for allow exit syscall */
		shctx->magic_token = rand(); 
		pid = fork();
		if(pid == 0){
			__SABX_Executor(sx->seg);
		}
		while(!got_child_signal);
		kill(pid, SIGUSR1);

		ret = __SABX_WaitForExecution(pid);
		if(ret == 1){ // The request contains a syscall 
			LOG(POLYLOG_PRIORITY_WARN,"Shellcode detected on segment");
			sx->total_shellcodes ++;
			break;
		}else{
			if(ret == 2) {
				shctx->jump_offset ++;
        			EXSG_SetJumpOffsetOnExecutableSegment(sx->seg,shctx->jump_offset);	
			}		
		}
		/* update the magic token for allow exit syscall */
		shctx->magic_token = rand(); 
	}while(shctx->jump_offset < shctx->max_jump_offset);


	LOG(POLYLOG_PRIORITY_INFO,
               	"Analisys done");
	COXT_Printf(shctx);
	sx->total_executed++;

	EXSG_DestroyExecutableSegment(sx->seg);
	return ret;
}
