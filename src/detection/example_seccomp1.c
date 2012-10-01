#include <stdio.h>
#include <seccomp.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>

scmp_filter_ctx InitSeccomp(void) {
	int rc = 0;
	scmp_filter_ctx ctx = NULL;

        ctx = seccomp_init(SCMP_ACT_KILL);
	if(ctx == NULL)
		goto out; 

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1,
				    SCMP_A0(SCMP_CMP_EQ, STDIN_FILENO));
	if (rc != 0)
		goto out;
	//rc = seccomp_export_pfc(ctx, STDOUT_FILENO);
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
				    SCMP_A0(SCMP_CMP_EQ, STDOUT_FILENO));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
				    SCMP_A0(SCMP_CMP_EQ, STDERR_FILENO));
	if (rc != 0)
		goto out;

        rc = seccomp_rule_add_exact(ctx,  SCMP_ACT_KILL, SCMP_SYS(open), 0);
	if (rc != 0)
		goto out;
	printf("Hooks load\n");
	rc = seccomp_load(ctx);
	printf("rc=%d\n",rc);
out:
	rc = seccomp_export_pfc(ctx, STDOUT_FILENO);
	printf("rc result %d\n",rc);
	return ctx;
}


int main(int argc, char *argv[])
{
	int ret;
	pid_t pid;

	scmp_filter_ctx ctx = NULL;
	struct stat status_buf;
	
	ctx = InitSeccomp();
	if(ctx == NULL) {
		perror("seccomp");
		exit(-1);
	}
	printf("done\n");

	ret = stat("/tmp/pepe",&status_buf);	
	if(ret == -1) {
		perror("stat");
	}	
	seccomp_release(ctx);
	return 0;	
}

