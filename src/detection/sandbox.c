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
static ST_SharedContext *ctx = NULL; 
int got_child_signal;

/**
 * SABX_Init - Creates a ST_Sandox struct 
 *
 * @return ST_Sandbox 
 *
 */
ST_Sandbox *SABX_Init() {
	ST_Sandbox *sand = g_new0(ST_Sandbox,1);

	sand->total_executed = 0;
	sand->total_shellcodes = 0;

       /* parent and child shares a context */
        sand->ctx = COXT_GetContext();
	
	sandbox = sand; // this is ugly :( TODO	
	ctx = sand->ctx;
	return sand;
}

/**
 * SABX_Destroy - Free a ST_Sandox struct 
 *
 * @param sx 
 *
 */
void SABX_Destroy(ST_Sandbox *sx){

	if(sx->seg!= NULL) {
		EXSG_DestroyExecutableSegment(sx->seg);
	}
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
	COXT_Printf(sx->ctx);	

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

        ret = seccomp_rule_add_exact(SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
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
                "child(%d) receives signal %d on virtualeip %d",getpid(),sig,ctx->virtualeip);
#endif
	printf("child(%d) receives signal(%d)size(%d)virtualeip(%d)\n",getpid(),sig,seg->executable_segment_size,seg->virtualeip);
        if((seg->virtualeip>=seg->executable_segment_size)||(seg->virtualeip < 0)) {
#ifdef DEBUG
                LOG(POLYLOG_PRIORITY_DEBUG,
                        "child(%d) Overflow exit on virtualeip=%d size=%d",getpid(),
                        ctx->virtualeip ,ctx->size);
#endif
                seg->virtualeip = seg->executable_segment_size;
                exit(ctx->magic_token);
        }

	ctx->total_segs_by_child++;
	EXSG_IncreaseEIPOnExecutableSegment(seg);
	EXSG_PrintExecutableSegment(seg);
	EXSG_ExecuteExecutableSegment(seg);

        exit(0);
        return;
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
        sigaction(SIGILL, &sa, NULL); // Illegal Instruction

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
void __SABX_Executor(ST_ExecutableSegment *sg,int magic_token) {
        int ret;

	ctx->child_pid = getpid();
	ctx->parent_pid = getppid();
	ctx->total_forks++;

	__SABX_SetSignalHandlers();       

        printf("child executing with magic_token(%d)\n",magic_token);
	kill(getppid(), SIGUSR1);
	while(!got_child_signal);

        ret = __SABX_InitSandbox(magic_token);
        fprintf(stdout,"child on seccomp sandbox ret = %d\n",ret);

        EXSG_ExecuteExecutableSegment(sg);

        exit(magic_token);
}

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

        printf("parent waiting for %d\n",pid);
        status = waitid(P_PID,pid,&sig,WEXITED|WSTOPPED|WCONTINUED|WNOWAIT);
        status = sig.si_pid;
        int ifexisted = WIFEXITED(status);
        int ifexisstatus = WEXITSTATUS(status);
        int ifsignaled = WIFSIGNALED(status);

        switch(sig.si_code){
                case CLD_EXITED:
                        printf("child exists correct\n");
                        break;
                case CLD_KILLED:
			if(sig.si_status == SIGSYS) {
                        	printf("child killed by seccomp\n");
				ret = 1;
			}else{
				printf("child killed by other reason\n");
			}
                        break;
        }
        printf("status(%d)si_pid(%d)si_code(%d)si_status(%d)\n",status,sig.si_pid,sig.si_code,sig.si_status);
        printf("process return status = %d,ifexisted=%d,ifexitstatus=%d,ifsignaled=%d\n",
                status,ifexisted,ifexisstatus,ifsignaled);
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
	int magic_token = 12;
	pid_t pid;
	int status;

	got_child_signal = 0;
	signal(SIGUSR1, __SABX_SigUsrSignalHandler);

	sx->ctx->magic_token = magic_token;
	sx->seg = EXSG_InitExecutableSegment();
        EXSG_PrepareExecutableSegment(sx->seg,buffer,size);
	
	pid = fork();
	if(pid == 0){
		__SABX_Executor(sx->seg,magic_token);
	}
	while(!got_child_signal);
        kill(pid, SIGUSR1);
	waitpid(pid,&status,0);

	ret = __SABX_WaitForExecution(pid);
	if(ret == 1)
		sx->total_shellcodes ++;
	sx->total_executed++;

	EXSG_DestroyExecutableSegment(sx->seg);

	return ret;
}
