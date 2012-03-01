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

#include "suspicious.h"
#include "syscalls.h"
#include "linux_syscalls.h"
#include "freebsd_syscalls.h"
#include "pvtrace.h"

#define POLYLOG_CATEGORY_NAME POLYVACCINE_DETECTION_INTERFACE ".tracer"
#include "log.h"

static ST_Tracer *tracer = NULL;
static ST_SharedContext *ctx = NULL; 

/**
 * Prints a buffer, just for debugging pourposes. 
 *
 * @param payload pointer to the buffer 
 * @param size of the buffer 
 */
void printfhex(char *payload,int size) {
        char buffer[10];
        int i,fd;
        const u_char *ptr;
        int online = 0;

        ptr = payload;
        write(0,"\n",1);
        for ( i= 0;i<size;i++) {
                if ( online == 16 ) {
                        write(0,"\n",1);
                        online = 0;
                }
                online ++;
                sprintf(buffer,"%02x ",*ptr);
                write(0,buffer,strlen(buffer));
                ptr++;
        }
        write(0,"\n",1);
        return;
}

/**
 * SYSU_Init - Initialize the main structs for trace process.
 *
 */
void SYSU_Init(){
	ST_SysCallSuspicious *sys = &ST_SysCallSuspiciousTable[0];
	ST_SyscallNode *n = &ST_SyscallTable[0];
	int i,j;
	tracer = (ST_Tracer*)malloc(sizeof(ST_Tracer)); 
	tracer->syscalls = g_hash_table_new(g_direct_hash,g_direct_equal);
	tracer->syscalltable = g_hash_table_new(g_direct_hash,g_direct_equal);
	tracer->flow = NULL;
	tracer->show_execution_path = FALSE;
	tracer->block_syscalls_eax = FALSE;

	/* parent and child shares a context */
	ctx = COXT_GetContext();

	ctx->parent_pid = getpid();	
        tracer->original_segment = NULL;
        tracer->segment_with_opcodes = NULL;
        tracer->executable_segment = NULL;
        tracer->original_segment_size = 0;
        tracer->executable_segment_size = 0;

	i = 0;
	while((sys!=NULL)&&(sys->number>0)) {
                g_hash_table_insert(tracer->syscalls,GINT_TO_POINTER(sys->number),sys);
		LOG(POLYLOG_PRIORITY_INFO,
                	"register callback '%s' reg = %d on hashtable(0x%x)",sys->name,sys->number,tracer->syscalls);
		i++;
		sys = &ST_SysCallSuspiciousTable[i];
        }
	j = 0;	
	while((n!=NULL)&&(n->name!=NULL)) {
		g_hash_table_insert(tracer->syscalltable,GINT_TO_POINTER(n->number),n);
		j++;
		n = &ST_SyscallTable[j];
	}
	LOG(POLYLOG_PRIORITY_INFO,"syscalls avaiable %d, loaded %d",j,i);
        return ;
}

void SYSU_BlockDetectedSyscalls(int value) {
	tracer->block_syscalls_eax = value;
	return;
}

void SYSU_ShowExecutionPath(int value){
	tracer->show_execution_path = value;
}

/**
 * SYSU_DestroySuspiciousSyscalls - Destroys the syscalls generated by a process.
 *
 */

void SYSU_DestroySuspiciousSyscalls(){
	GSList *l = tracer->flow;

	while(l!= NULL) {
		GSList *item = g_slist_nth(l,0);
		if (item != NULL) {
			l = g_slist_remove_link(l,item);
			ST_SysCall *s = (ST_SysCall*)item->data;
			SUSY_Destroy(s);
		}
	}
	tracer->flow = NULL;
	return;
}


void SYSU_PrintSuspiciousSysCalls(){
	GSList *l = tracer->flow;

	while(l!= NULL) {
		ST_SysCall *s = (ST_SysCall*)l->data;
		SUSY_Printf(s);
		l = g_list_next(l);
	}
}

void SYSU_Destroy(){
        g_hash_table_destroy(tracer->syscalls);

	SYSU_PrintSuspiciousSysCalls();
	SYSU_DestroySuspiciousSyscalls();
	
	g_slist_free(tracer->flow);
	free(tracer);
//	tracer = NULL;
	return;
}

void SYSU_Stats() {
        GHashTableIter iter;
        gpointer k,v;

	fprintf(stdout,"Tracer statistics\n");
	fprintf(stdout,"\texecutions by tracer %d\n",ctx->incbytracer);
	fprintf(stdout,"\texecutions by child %d\n",ctx->incbychild);
        fprintf(stdout,"\tExecuted syscalls\n");
        g_hash_table_iter_init (&iter, tracer->syscalltable);
        while (g_hash_table_iter_next (&iter, &k, &v)) {
                ST_SyscallNode *nod = (ST_SyscallNode*)v;
		if(nod->matchs>0) 
                	fprintf(stdout,"\t\tsyscall(%s)matchs(%d)\n",nod->name,nod->matchs);
        }

	return;
}

void SYSU_Kill(pid_t pid, int sig) {
        int i = kill(pid, sig);
        if (i) {
                perror("kill");
                exit(ERROR_KILL);
        }
	return;
}

void SYSU_Exit() {
	//SYSU_Destroy();
	SYSU_Kill(ctx->child_pid,SIGKILL);
	SYSU_Destroy();
//	SYSU_Kill(ctx->parent_pid,SIGKILL);
	return;
}	

int SYSU_Wait(pid_t p, int report, int stopsig) {
        int status;
        int i;

	if(waitpid(p,&status,0)< 0){
                perror("wait");
                return PROCESS_EXIT;
        }
        i = status;
        if (i > 255) i = i % 256;
        if (i >= 129) i = i - 127;

/**
       WIFEXITED(status)
              returns true if the child terminated normally, that is, by calling exit(3) or _exit(2), or by returning from main().

       WEXITSTATUS(status)
              returns  the  exit  status of the child.  This consists of the least significant 8 bits of the status argument that the child
              specified in a call to exit(3) or _exit(2) or as the argument for a return statement in main().  This macro  should  only  be
              employed if WIFEXITED returned true.

       WIFSIGNALED(status)
              returns true if the child process was terminated by a signal.

       WTERMSIG(status)
              returns  the  number of the signal that caused the child process to terminate.  This macro should only be employed if WIFSIG‐
              NALED returned true.

       WCOREDUMP(status)
              returns true if the child produced a core dump.  This macro should only be employed if WIFSIGNALED returned true.  This macro
              is  not  specified  in  POSIX.1-2001  and  is  not  available on some Unix implementations (e.g., AIX, SunOS).  Only use this
              enclosed in #ifdef WCOREDUMP ... #endif.

       WIFSTOPPED(status)
              returns true if the child process was stopped by delivery of a signal; this is only possible if the call was done using  WUN‐
              TRACED or when the child is being traced (see ptrace(2)).

       WSTOPSIG(status)
              returns  the  number of the signal which caused the child to stop.  This macro should only be employed if WIFSTOPPED returned
              true.

       WIFCONTINUED(status)
              (since Linux 2.6.10) returns true if the child process was resumed by delivery of SIGCONT.
*/

/*

#ifdef DEBUG
	int ifexisted = WIFEXITED(status);
	int ifexisstatus = WEXITSTATUS(status);
	int ifsignaled = WIFSIGNALED(status);
	int termsig = WTERMSIG(status);
	int coredump = WCOREDUMP(status);
	int ifstoped = WIFSTOPPED(status);
	int ifstopsig = WSTOPSIG(status);
	int ifcontinued = WIFCONTINUED(status);
        int byusr1 = 0;
        int bysigstop = 0;

        if(WSTOPSIG(status) == SIGUSR1)
                byusr1=1;

        if(WSTOPSIG(status) ==SIGTRAP)
                bysigstop = 1;

	printf("Process %d generates the next status offset=%d\n",p,ctx->virtualeip);
	printf("\tifexited=%d;ifexitstatus=%d;",ifexisted,ifexisstatus);
	printf("ifsignaled=%d;termsig=%d\n",ifsignaled,termsig);
	printf("\tcoredump=%d;ifstoped=%d;",coredump,ifstoped);
	printf("ifstopsig=%d;ifcontinued=%d\n",ifstopsig,ifcontinued);
	printf("\tbysigusr=%d;bysigtrap=%d\n",byusr1,bysigstop);
#endif
*/

//	printf("---status = %d i=%d\n",status,i);
        //ST_ProcessExitCodes[i].received ++;
        /*
         * Report only unexpected things.
         *
         * The conditions WIFEXITED, WIFSIGNALED, WIFSTOPPED
         * are mutually exclusive:
         * WIFEXITED:  (status & 0x7f) == 0, WEXITSTATUS: top 8 bits
         * and now WCOREDUMP:  (status & 0x80) != 0
         * WIFSTOPPED: (status & 0xff) == 0x7f, WSTOPSIG: top 8 bits
         * WIFSIGNALED: all other cases, (status & 0x7f) is signal.
         */
        if (WIFEXITED(status) && !(report & EXPECT_EXITED)) {
                //fprintf(stdout, "ERROR:child exited%s with status %d\n",
                 //       WCOREDUMP(status) ? " and dumped core" : "",
                  //      WEXITSTATUS(status));
		return PROCESS_EXIT;
	}
//        if (WIFSTOPPED(status) && !(report & EXPECT_STOPPED))
 //               fprintf(stdout, "ERROR:child stopped by signal %d\n",
                        //WSTOPSIG(status));
  //      if (WIFSIGNALED(status) && !(report & EXPECT_SIGNALED))
   //             fprintf(stdout, "ERROR:child signalled by signal %d\n",
    //                    WTERMSIG(status));

        if (WIFSTOPPED(status) && WSTOPSIG(status) != stopsig) {
                /* a different signal - send it on and wait */
               // fprintf(stdout, "ERROR:Waited for signal %d, got %d\n",
                //        stopsig, WSTOPSIG(status));
                if ((WSTOPSIG(status) & 0x7f) == (stopsig & 0x7f))
                        return PROCESS_RUNNING;

		PTRC_TraceSyscall(p,WSTOPSIG(status));	
                //SYSU_PTraceVoid(TRACE_SYSCALL, p, 0, (void*) WSTOPSIG(status));
                return SYSU_Wait(p, report, stopsig);
        }

        if ((report & EXPECT_STOPPED) && !WIFSTOPPED(status)) {
                fprintf(stdout, "ERROR:Not stopped?\n");
		return PROCESS_EXIT;
        }
	return PROCESS_RUNNING;
}

/*
 * A child stopped at a syscall has status as if it received SIGTRAP.
 * In order to distinguish between SIGTRAP and syscall, some kernel
 * versions have the PTRACE_O_TRACESYSGOOD option, that sets an extra
 * bit 0x80 in the syscall case.
 */
#define SIGSYSTRAP      (SIGTRAP | sysgood_bit)

int sysgood_bit = 0;

void SYSU_SetSysGood(pid_t p) {
#ifdef PTRACE_O_TRACESYSGOOD
        int i = ptrace(PTRACE_SETOPTIONS, p, 0, (void*) PTRACE_O_TRACESYSGOOD);
        if (i == 0)
                sysgood_bit = 0x80;
        else
                perror("PTRACE_O_TRACESYSGOOD");
#endif
}

void SYSU_AddSuspiciousSyscall(ST_Tracer *t,char *name,struct user_regs_struct *u,int status) {
	ST_SysCall *sys = (ST_SysCall*)SUSY_New(name,u,status); 

	t->flow = g_slist_append(t->flow,sys);
	return;
}

int got_child_signal = 0;

/**
 * SYSU_NewExecutionProcess - Executes a segment memory zone by the child process.
 *
 * @param c a ST_SharedContext share with the parent 
 *  
 */

#define POLYLOG_CATEGORY_NAME POLYVACCINE_DETECTION_INTERFACE ".tracer.child"

void SYSU_NewExecutionProcess(ST_SharedContext *c) {
        char *pointer;
        void (*function)();
	int i,status;

	LOG(POLYLOG_PRIORITY_DEBUG,
        	"child(%d) preparing to execute %d bytes from offset %d",getpid(),ctx->size,ctx->virtualeip);
	LOG(POLYLOG_PRIORITY_DEBUG,
        	"child(%d) istracedchild=%d,parent_pid=%d",getpid(),ctx->isptracechild,ctx->parent_pid);
	LOG(POLYLOG_PRIORITY_DEBUG,
        	"child(%d) size=%d",getpid(),ctx->size);
	if (ctx->isptracechild == FALSE) {

                if((ctx->virtualeip >= ctx->size)||(ctx->virtualeip < 0)) {
			LOG(POLYLOG_PRIORITY_DEBUG,
                        	"child(%d) Overflow exit",getpid());
                        ctx->virtualeip = ctx->size;
                        exit(0);
                }
		PTRC_TraceMe();
//                SYSU_PTraceVoid(TRACE_TRACEME, 0, NULL, SIGUSR1);
                SYSU_Kill(ctx->parent_pid, SIGUSR1);
                ctx->isptracechild = TRUE;
                while (!got_child_signal);
		/* At this momment al the steps taked by the process are traced */
        }
        function = (void (*)(void)) ctx->memory;
        (*function)();
        return;
}

#define POLYLOG_CATEGORY_NAME POLYVACCINE_DETECTION_INTERFACE ".tracer"

/**
 * SYSU_TraceProcess - Traces a child process and check if there is any syscall.
 *
 * @param t ST_Tracer
 * @param child_pid 
 *  
 */

int SYSU_TraceProcess(ST_Tracer *t, pid_t child_pid){
        int ret,syscall;
#ifdef __LINUX__
	struct user_regs_struct u_in;
#endif
#ifdef __FREEBSD__
	struct reg u_in;
#endif

        SYSU_Kill(child_pid, SIGUSR1);
        ret = SYSU_Wait(child_pid, EXPECT_STOPPED, SIGUSR1);
        if (ret != PROCESS_RUNNING) {
                fprintf(stdout,"Tracer %d, Bad Child %d\n",getpid(),child_pid);
                return 0;
        }

//       	SYSU_SetSysGood(child_pid);
	PTRC_TraceSyscall(child_pid,SIGUSR1);
//	SYSU_PTraceVoid(TRACE_SYSCALL, child_pid, TRACE_O_TRACEFORK, (void*)SIGUSR1);
	SYSU_DestroySuspiciousSyscalls();
	LOG(POLYLOG_PRIORITY_INFO,
		"parent(%d)ready for child execution",getpid());
        alarm(3);
        while(1) {
                struct ST_SysCallFlow *scf;
		ST_SysCallSuspicious *sus;
		ST_SyscallNode *nod;
                ret = PROCESS_RUNNING;
		char *syscall_name;

                ret = SYSU_Wait(child_pid, EXPECT_STOPPED, SIGSYSTRAP);
                if (ret == PROCESS_RUNNING) { /* Process still running */
			PTRC_TraceGetRegisters(child_pid,&u_in);

			syscall = REG_AX(u_in);
			nod = (ST_SyscallNode*)g_hash_table_lookup(tracer->syscalltable,GINT_TO_POINTER(syscall));
			if(nod) {
				syscall_name = nod->name;
				nod->matchs++;

				sus = (ST_SysCallSuspicious*)g_hash_table_lookup(tracer->syscalls,GINT_TO_POINTER(syscall));
				if(sus != NULL) {
					if (sus->level == SYSCALL_LEVEL_HIGH) {
						SYSU_AddSuspiciousSyscall(t,syscall_name,&u_in,0);		
						LOG(POLYLOG_PRIORITY_WARN,
							"High suspicious syscall %s on memory",syscall_name);
						LOG(POLYLOG_PRIORITY_WARN,
							"\tax=%x;bx=%x;cx=%x;dx=%x",REG_AX(u_in),REG_BX(u_in),REG_CX(u_in),REG_DX(u_in));
						LOG(POLYLOG_PRIORITY_WARN,
							"\tcs=%x;ip=%x;di=%x;si=%x",REG_CS(u_in),REG_IP(u_in),REG_DI(u_in),REG_SI(u_in));

						if(t->show_execution_path== TRUE) 
							SYSU_PrintSuspiciousSysCalls();
						if(t->block_syscalls_eax==TRUE){
							REG_AX(u_in) = 0xbeefbeef;
							PTRC_TraceSetRegisters(child_pid,&u_in);
//							SYSU_PTraceVoid(TRACE_SETREGS,child_pid,NULL,&u_in);
							LOG(POLYLOG_PRIORITY_WARN,
								"modifying syscall number rax=%x, process continue execution",syscall);
						}else {			
							kill(child_pid,SIGKILL);
							PTRC_TraceKill(child_pid);
							LOG(POLYLOG_PRIORITY_WARN,
								"process %d killed by parent",child_pid);
                                        		alarm(0);
                                        		return 1;
						}
					}
					if (sus->level == SYSCALL_LEVEL_MEDIUM) {
						LOG(POLYLOG_PRIORITY_WARN,
							"medium suspicious syscall %s on memory",syscall_name);
					}
                                }else{
					LOG(POLYLOG_PRIORITY_WARN,
						"unsupported syscall number %d",syscall);
				}
                        }
//                        SYSU_PTraceVoid(TRACE_SYSCALL, child_pid, 0, 0);
			PTRC_TraceSyscall(child_pid,0);
                }else
                        break;
        }
	if(t->show_execution_path== TRUE) 
		SYSU_PrintSuspiciousSysCalls();
        alarm(0);
        return 0;
}

void SYSU_HandlerAlarmNew (int sig) {
        int ret;
        int status;

	LOG(POLYLOG_PRIORITY_DEBUG,
        	"process %d consume too much CPU on offset %d",ctx->child_pid);//,sc_floweip->child_pid,sc_floweip->virtualeip);
//        sc_floweip->cpu_execed ++;
 //       sc_floweip->virtualeip = sc_floweip->size;
        kill(ctx->child_pid,SIGKILL);
        ret = waitpid(ctx->child_pid,&status,WNOHANG|WUNTRACED);
        return;
}


void sigusr(int signal) {
        got_child_signal = 1;
	return;
}

#define POLYLOG_CATEGORY_NAME POLYVACCINE_DETECTION_INTERFACE ".tracer.child"

void sigsegv_handler(int sig, siginfo_t *info, void *data) {
	LOG(POLYLOG_PRIORITY_DEBUG,
		"child(%d) receives signal %d on virtualeip %d",getpid(),sig,ctx->virtualeip);

        if((ctx->virtualeip>=ctx->size)||(ctx->virtualeip < 0)) {
		LOG(POLYLOG_PRIORITY_DEBUG,
                	"child(%d) Overflow exit on virtualeip=%d size=%d",getpid(),
			ctx->virtualeip ,ctx->size);
                ctx->virtualeip = ctx->size;
                exit(0);
        }
        memcpy(tracer->executable_segment ,
		tracer->segment_with_opcodes,tracer->executable_segment_size);              /* Copy the Buffer */
        ctx->virtualeip ++;
        memcpy(tracer->executable_segment + 9 ,&(ctx->virtualeip),4);

        ctx->isptracechild == TRUE;
        ctx->incbychild++;
        SYSU_NewExecutionProcess(ctx);
        exit(0); // añadido el 4 noviembrE
        return;
}


#define POLYLOG_CATEGORY_NAME POLYVACCINE_DETECTION_INTERFACE ".tracer"

int SYSU_AnalyzeSegmentMemory(char *buffer, int size, ST_TrustOffsets *t_off){
	void (*oldsig)(int);
        struct sigaction sact;
	struct sigaction susr;
        pid_t child_pid,parent_pid;
        int ret,real_size,init_regs_size,jump_size;
	int offset = 0;

        sigemptyset( &sact.sa_mask );
        sact.sa_flags = 0;
        sact.sa_handler = SYSU_HandlerAlarmNew;
        sigaction( SIGALRM, &sact, NULL );

	oldsig = signal(SIGUSR1, sigusr);
	if (oldsig == SIG_ERR) {
		perror("signal");
		exit(1);
	}
 
       	tracer->original_segment = buffer;
        tracer->original_segment_size = size;

#if __WORDSIZE == 64 // 64 Bits machine
	jump_size = 5;
	init_regs_size = 12;
	real_size = size + init_regs_size + jump_size; 
#else
	jump_size = 5;
	init_regs_size = 8;
	real_size = size + init_regs_size + jump_size; 
#endif

        tracer->executable_segment_size = real_size;
        tracer->executable_segment = mmap(0, tracer->executable_segment_size, 
		PROT_EXEC|PROT_READ|PROT_WRITE, MAP_SHARED|SEGMENT_EXECUTABLE|SEGMENT_ANONYMOUS, -1, 0);
        if (tracer->executable_segment == MAP_FAILED) {
		perror("mmap");
                return 0;
        }

	memset(tracer->executable_segment,"\x90",real_size);              /* Init all with nops */
#if __WORDSIZE == 64
        memcpy(tracer->executable_segment,"\x48\x31\xc0" "\x48\x31\xdb" "\x48\x31\xc9" "\x48\x31\xd2",init_regs_size);/* Init Registers */
#else
        memcpy(tracer->executable_segment,"\x31\xc0" "\x31\xc9" "\x31\xdb" "\x31\xd2",init_regs_size);/* Init Registers */
#endif
	/* Makes a jmp to next instruction */
        memcpy(tracer->executable_segment + init_regs_size ,"\xe9\x00\x00\x00\x00",jump_size); 
	/* Copy the offset Jmp Jump */
        memcpy(tracer->executable_segment + (init_regs_size + 1) ,&offset ,4);            
	/* Copy the Buffer */
        memcpy(tracer->executable_segment + init_regs_size + jump_size ,buffer,tracer->executable_segment_size);

	tracer->segment_with_opcodes = malloc(tracer->executable_segment_size);
        memcpy(tracer->segment_with_opcodes,tracer->executable_segment,tracer->executable_segment_size);

	ctx->t_off = t_off;
	ctx->t_off->index = 0;
        ctx->memory = tracer->executable_segment;
	parent_pid = getpid();
        ctx->parent_pid = getpid();
        ctx->size = tracer->executable_segment_size;
	int index = 0;

	ctx->virtualeip = 0;
	do {

		// TODO check all the trusted offsets to avoid fork operations
		if((t_off->offsets_start[index]==0)&&(t_off->offsets_end[index]>0) ){
			DEBUG0("avoid offset %d due to is trusted (%d,%d)\n",
				ctx->virtualeip,t_off->offsets_start[index],t_off->offsets_end[index]);
			ctx->virtualeip = t_off->offsets_end[index]+1;
			index++;	
		}	
		ctx->isptracechild = FALSE;
		ctx->incbytracer++;
		got_child_signal = 0;
		LOG(POLYLOG_PRIORITY_DEBUG,
                	"tracer(%d) Forking Process from offset %d of %d bytes",getpid(),ctx->virtualeip,ctx->size);
                child_pid = fork();
                if (child_pid == 0) {
        		struct sigaction sa;
			
                        sigemptyset (&sa.sa_mask);
                        sa.sa_sigaction = (void *)sigsegv_handler;
                        sa.sa_flags = SA_RESTART | SA_NODEFER; // el flag SA_NODEFER es el que hace que se itere 
			
                        sigaction(SIGSEGV, &sa, NULL); // Invalid memory Reference 
                        sigaction(SIGILL, &sa, NULL); // Illegal Instruction 
                        sigaction(SIGABRT, &sa, NULL);
                        sigaction(SIGBUS, &sa, NULL);
                        sigaction(SIGFPE, &sa, NULL);
                        sigaction(SIGPIPE, &sa, NULL);
                        sigaction(SIGKILL, &sa, NULL);

                        sigaction(SIGSTOP, &sa, NULL);

                        signal(SIGINT,SIG_DFL);

                     	ctx->child_pid = getpid();

			/* copy the jmp address to the next offset */ 
                        memcpy(tracer->executable_segment + (init_regs_size + 1) ,&(ctx->virtualeip) ,4);
                        if((ctx->virtualeip > ctx->size)||(ctx->virtualeip < 0)) {
                                ctx->virtualeip = ctx->size;
				//DEBUG_TRACER("Avoid overflow execution,virtualeip(%d)size(%d)\n",ctx->virtualeip,ctx->size);
                                exit(0);
                        }
                        SYSU_NewExecutionProcess(ctx);
                        exit(0);
                }
                while (!got_child_signal); 
		ctx->child_pid = child_pid;
		ret = SYSU_TraceProcess(tracer,child_pid);
                if (ret == 1) {
                        munmap(tracer->executable_segment,tracer->executable_segment_size);
			free(tracer->segment_with_opcodes);
                        ctx->memory = NULL;
                        return 1;
                }
		ctx->virtualeip++;	
	}while(ctx->virtualeip < ctx->size);
	
        munmap(tracer->executable_segment,tracer->executable_segment_size);
	free(tracer->segment_with_opcodes);
        ctx->memory = NULL;
        return 0;
}


