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

static ST_Tracer *tracer = NULL;
static ST_SharedContext *ctx = NULL; 

#define IA32_LINUX_EXIT_CODES 34
static ST_ProcessExitCode ST_ProcessExitCodes[IA32_LINUX_EXIT_CODES] = {
        { 0,            "Exit Correct",                         0},
        { SIGHUP,       "SigHUp",                       0},
        { SIGINT,       "SigInt",                       0},
        { SIGQUIT,      "SigQuit",                       0},
        { SIGILL,       "Illegal Instruction",                  0},
        { SIGTRAP,      "SigTrap",               0},
        { SIGABRT,      "Abort Signal",                         0},
        { SIGBUS,       "SigBus",               0},
        { SIGFPE,       "Floating point exception",             0},
        { SIGKILL,      "Kill Signal",                          0},
        { SIGUSR1,      "User Signal 1",               0},
        { SIGSEGV,      "Invalid memory reference",             0},
        { SIGUSR2,      "User Signal 2",               0},
        { SIGPIPE,      "SigPipe",               0},
        { SIGALRM,      "SigAlarm",               0},
        { SIGTERM,      "SigTerm",               0},
        { SIGSTKFLT,    "SigHUp",               0},
        { SIGCHLD,      "SigHUp",               0},
        { SIGCONT,      "SigHUp",               0},
        { SIGSTOP,      "SigStop",               0},
        { SIGTSTP,      "SigHUp",               0},
        { SIGTTIN,      "SigHUp",               0},
        { SIGTTOU,      "SigHUp",               0},
        { SIGURG,       "SigHUp",               0},
        { SIGXCPU,      "SigXcpu",               0},
        { SIGXFSZ,      "SigHUp",               0},
        { SIGVTALRM,    "SigHUp",               0},
        { SIGPROF,      "SigHUp",               0},
        { SIGWINCH,     "SigHUp",               0},
        { SIGIO,        "SigIO & SigPoll",              0},
        { SIGPWR,       "SigHUp",               0},
        { SIGSYS,       "SigHUp",               0},
        { SIGUNUSED,    "SigHUp",               0}
};

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
	int i;
	tracer = (ST_Tracer*)malloc(sizeof(ST_Tracer)); 
	tracer->syscalls = g_hash_table_new(g_direct_hash,g_direct_equal);
	tracer->flow = NULL;

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

                DEBUG0("register callback '%s' reg = %d on hashtable(0x%x)\n",sys->name,sys->number,tracer->syscalls);
		i++;
		sys = &ST_SysCallSuspiciousTable[i];
        }
        return ;
}

void SYSU_DestroySuspiciousSyscalls(){
	GSList *l = tracer->flow;

	while(l!= NULL) {
		GSList *item = g_slist_nth(l,0);
		if (item != NULL) {
			l = g_slist_remove_link(l,item);
			ST_SysCall *s = (ST_SysCall*)item->data;
			DEBUG0("destroy suspicious syscall(0x%x) '%s'\n",s,s->name);
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
	GSList *l = tracer->flow;
	ST_SysCall *s = NULL;
	register int i;

        for (i = 0;i<g_slist_length(tracer->flow);i++){
                GSList *item = g_slist_nth(tracer->flow,0);
                if (item != NULL) {
                        tracer->flow = g_slist_remove_link(tracer->flow,item);
                        s = (ST_SysCall*)item->data;
                        SUSY_Destroy(s);
                }
        }
	SYSU_PrintSuspiciousSysCalls();
	g_slist_free(tracer->flow);
	free(tracer);
	tracer = NULL;
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
	SYSU_Destroy();
	SYSU_Kill(ctx->child_pid,SIGKILL);
	SYSU_Kill(ctx->parent_pid,SIGKILL);
	return;
}	

void SYSU_PTraceVoid(int request, pid_t pid, void *addr, void *data) {
        int i = ptrace(request, pid, addr, data);
        if (i) {
                fprintf(stderr,"Can not ptrace process %d \n",pid);
		SYSU_Exit();
        }
        return;
}


int SYSU_Wait(pid_t p, int report, int stopsig) {
        int status;
        int i;
        pid_t pw = wait(&status);

        if (pw == (pid_t) -1) {
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

	printf("Process %d generates the next status offset=%d\n",p,ctx->virtualeip);
	printf("\tifexited=%d;ifexitstatus=%d;",ifexisted,ifexisstatus);
	printf("ifsignaled=%d;termsig=%d\n",ifsignaled,termsig);
	printf("\tcoredump=%d;ifstoped=%d;",coredump,ifstoped);
	printf("ifstopsig=%d;ifcontinued=%d\n",ifstopsig,ifcontinued);
	printf("\tifstopsigname=%s\n",ST_ProcessExitCodes[ifstopsig].description);
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
                fprintf(stdout, "ERROR:child exited%s with status %d\n",
                        WCOREDUMP(status) ? " and dumped core" : "",
                        WEXITSTATUS(status));
		return PROCESS_EXIT;
	}
        if (WIFSTOPPED(status) && !(report & EXPECT_STOPPED))
                fprintf(stdout, "ERROR:child stopped by signal %d\n",
                        WSTOPSIG(status));
        if (WIFSIGNALED(status) && !(report & EXPECT_SIGNALED))
                fprintf(stdout, "ERROR:child signalled by signal %d\n",
                        WTERMSIG(status));

        if (WIFSTOPPED(status) && WSTOPSIG(status) != stopsig) {
                /* a different signal - send it on and wait */
                fprintf(stdout, "ERROR:Waited for signal %d, got %d\n",
                        stopsig, WSTOPSIG(status));
                if ((WSTOPSIG(status) & 0x7f) == (stopsig & 0x7f))
                        return PROCESS_RUNNING;
                SYSU_PTraceVoid(PTRACE_SYSCALL, p, 0, (void*) WSTOPSIG(status));
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

	DEBUG0("adding suspicious syscall(0x%x) '%s'\n",sys,sys->name);
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

void SYSU_NewExecutionProcess(ST_SharedContext *c) {
        char *pointer;
        void (*function)();
	int i,status;

        DEBUG0("Child(%d) preparing to execute %d bytes from offset %d\n",getpid(),ctx->size,ctx->virtualeip);
        DEBUG0("Child(%d) istracedchild=%d,parent_pid=%d\n",getpid(),ctx->isptracechild,ctx->parent_pid);
        if (ctx->isptracechild == FALSE) {

                if((ctx->virtualeip >= ctx->size)||(ctx->virtualeip < 0)) {
                        DEBUG0("Child(%d) Overflow exit\n",getpid());
                        ctx->virtualeip = ctx->size;
                        return;
                }
                SYSU_PTraceVoid(PTRACE_TRACEME, 0, NULL, NULL);
                SYSU_Kill(ctx->parent_pid, SIGUSR1);
                ctx->isptracechild = TRUE;
                while (!got_child_signal);
		/* At this momment al the steps taked by the process are traced */
        }
        function = (void (*)(void)) ctx->memory;
        (*function)();
        return;
}

/**
 * SYSU_TraceProcess - Traces a child process and check if there is any syscall.
 *
 * @param t ST_Tracer
 * @param child_pid 
 *  
 */

int SYSU_TraceProcess(ST_Tracer *t, pid_t child_pid){
        int ret,syscall;
	struct user_regs_struct u_in;

        SYSU_Kill(child_pid, SIGUSR1);
        ret = SYSU_Wait(child_pid, EXPECT_STOPPED, SIGUSR1);
        if (ret != PROCESS_RUNNING) {
                fprintf(stdout,"Tracer %d, Bad Child %d\n",getpid(),child_pid);
                return 0;
        }

        SYSU_SetSysGood(child_pid);
        SYSU_PTraceVoid(PTRACE_SYSCALL, child_pid, NULL, (void*)SIGUSR1);
	SYSU_DestroySuspiciousSyscalls();
        alarm(2);
        while(1) {
                struct ST_SysCallFlow *scf;
		ST_SysCallSuspicious *sus;
                ret = PROCESS_RUNNING;
		char *syscall_name;

                ret = SYSU_Wait(child_pid, EXPECT_STOPPED, SIGSYSTRAP);
                if (ret == PROCESS_RUNNING) { /* Process still running */
                        SYSU_PTraceVoid(PTRACE_GETREGS, child_pid, 0, &u_in);
#if __WORDSIZE == 64 // 64 Bits machine
                        syscall = u_in.orig_rax;
#else
			syscall = u_in.orig_eax;
#endif			
                        if (syscall-1 >= 0 && syscall-1 < SIZE(linux_syscallnames) && (syscall_name=linux_syscallnames[syscall])) {
				DEBUG0("Syscall '%s' detected on buffer\n",syscall_name);

				SYSU_AddSuspiciousSyscall(t,syscall_name,&u_in,0);

				sus = (ST_SysCallSuspicious*)g_hash_table_lookup(tracer->syscalls,GINT_TO_POINTER(syscall));
				if(sus != NULL) {
					if (sus->level == SYSCALL_LEVEL_HIGH) {
						WARNING("High suspicious syscall %s on memory\n",syscall_name);
#if __WORDSIZE == 64 // 64 Bits machine
						WARNING("\trax=%x;rbx=%x;rcx=%x;rdx=%x\n",u_in.orig_rax, u_in.rbx,u_in.rcx, u_in.rdx);
						WARNING("\trsi=%x;rdi=%x;cs=%x;rip=%x\n",u_in.rsi, u_in.rdi,u_in.cs, u_in.rip);
#else
						WARNING("rax=%x;rbx=%x;rcx=%x;rdx=%x\n",u_in.orig_eax, u_in.ebx,u_in.ecx, u_in.edx);
#endif
                                        	kill(child_pid,SIGKILL);
                                        	SYSU_PTraceVoid(PTRACE_KILL,child_pid,0, 0);
						WARNING("Process %d killed by parent\n",child_pid);
                                        	alarm(0);
                                        	return 1;
					}
					if (sus->level == SYSCALL_LEVEL_MEDIUM) {
						WARNING("Medium suspicious syscall %s on memory\n",syscall_name);
					}
                                }
                        }
                        SYSU_PTraceVoid(PTRACE_SYSCALL, child_pid, 0, 0);
                }else
                        break;
        }
        alarm(0);
	DEBUG0("return Analyzer\n");
        return 0;
}

void SYSU_HandlerAlarmNew (int sig) {
        int ret;
        int status;

        DEBUG0("Process %d consume too much CPU on offset %d\n",tracer->child_pid);//,sc_floweip->child_pid,sc_floweip->virtualeip);
//        sc_floweip->cpu_execed ++;
 //       sc_floweip->virtualeip = sc_floweip->size;
        kill(tracer->child_pid,SIGKILL);
        ret = waitpid(tracer->child_pid,&status,WNOHANG|WUNTRACED);
        return;
}


void sigusr(int signal) {
        got_child_signal = 1;
	return;
}

void sigsegv_handler(int sig, siginfo_t *info, void *data) {
        //ST_ProcessExitCodes[sig].received ++;
	//DEBUG0("Child receives signal %d on virtualeip %d\n",sig,ctx->virtualeip);
        //fprintf(stdout,"Signal %d on veip = %d\n",sig,sc_floweip->virtualeip);
        memcpy(tracer->executable_segment ,tracer->segment_with_opcodes,tracer->executable_segment_size);              /* Copy the Buffer */
        ctx->virtualeip ++;
        memcpy(tracer->executable_segment + 9 ,&(ctx->virtualeip),4);

        if((ctx->virtualeip>ctx->size)||(ctx->virtualeip < 0)) {
                ctx->virtualeip = ctx->size;
                exit(0);
        }
        ctx->isptracechild == TRUE;
        ctx->incbychild++;
        SYSU_NewExecutionProcess(ctx);
        exit(0); // añadido el 4 noviembrE
        return;
}




int SYSU_AnalyzeSegmentMemory(char *buffer, int size, int offset) {
	void (*oldsig)(int);
        struct sigaction sact;
	struct sigaction susr;
        pid_t child_pid,parent_pid;
        int ret,real_size,init_regs_size,jump_size;

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
		PROT_EXEC|PROT_READ|PROT_WRITE, MAP_SHARED|MAP_EXECUTABLE|MAP_ANONYMOUS, -1, 0);
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

        ctx->memory = tracer->executable_segment;
	parent_pid = getpid();
        ctx->parent_pid = getpid();
        ctx->size = tracer->executable_segment_size;
	int counter = 0;
        for (ctx->virtualeip = offset; ctx->virtualeip < ctx->size; ctx->virtualeip ++) {
		ctx->isptracechild = FALSE;
		ctx->incbytracer++;
		got_child_signal = 0;
                DEBUG0("Tracer(%d) Forking Process from offset %d of %d bytes\n",getpid(),ctx->virtualeip,ctx->size);
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
				printf("Avoid overflow execution,virtualeip(%d)size(%d)\n",ctx->virtualeip,ctx->size);
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
                        ctx->memory = NULL;
                        return 1;
                }
        }
        munmap(tracer->executable_segment,tracer->executable_segment_size);
        ctx->memory = NULL;
	DEBUG0("End segment execution\n");
        return 0;
}


