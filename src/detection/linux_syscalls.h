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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "syscallnode.h"

#ifdef __LINUX__
#if __WORDSIZE == 64 // 64 bits architecture

/* generated
 * grep define /usr/include/asm/unistd_64.h | awk '{print $2, $3}' | awk '{if (NF == 2) { name = substr($1,6); number=$2; printf("\t{ .name=\"%s\",\t\t.number=%s,\t.matchs=0 },\n",name,$1);}}'
 */ 

static struct ST_SyscallNode ST_SyscallTable [] = {
        { .name="read",         .number=__NR_read,      .matchs=0 },
        { .name="write",                .number=__NR_write,     .matchs=0 },
        { .name="open",         .number=__NR_open,      .matchs=0 },
        { .name="close",                .number=__NR_close,     .matchs=0 },
        { .name="stat",         .number=__NR_stat,      .matchs=0 },
        { .name="fstat",                .number=__NR_fstat,     .matchs=0 },
        { .name="lstat",                .number=__NR_lstat,     .matchs=0 },
        { .name="poll",         .number=__NR_poll,      .matchs=0 },
        { .name="lseek",                .number=__NR_lseek,     .matchs=0 },
        { .name="mmap",         .number=__NR_mmap,      .matchs=0 },
        { .name="mprotect",             .number=__NR_mprotect,  .matchs=0 },
        { .name="munmap",               .number=__NR_munmap,    .matchs=0 },
        { .name="brk",          .number=__NR_brk,       .matchs=0 },
        { .name="rt_sigaction",         .number=__NR_rt_sigaction,      .matchs=0 },
        { .name="rt_sigprocmask",               .number=__NR_rt_sigprocmask,    .matchs=0 },
        { .name="rt_sigreturn",         .number=__NR_rt_sigreturn,      .matchs=0 },
        { .name="ioctl",                .number=__NR_ioctl,     .matchs=0 },
        { .name="pread64",              .number=__NR_pread64,   .matchs=0 },
        { .name="pwrite64",             .number=__NR_pwrite64,  .matchs=0 },
        { .name="readv",                .number=__NR_readv,     .matchs=0 },
        { .name="writev",               .number=__NR_writev,    .matchs=0 },
        { .name="access",               .number=__NR_access,    .matchs=0 },
        { .name="pipe",         .number=__NR_pipe,      .matchs=0 },
        { .name="select",               .number=__NR_select,    .matchs=0 },
        { .name="sched_yield",          .number=__NR_sched_yield,       .matchs=0 },
        { .name="mremap",               .number=__NR_mremap,    .matchs=0 },
        { .name="msync",                .number=__NR_msync,     .matchs=0 },
        { .name="mincore",              .number=__NR_mincore,   .matchs=0 },
        { .name="madvise",              .number=__NR_madvise,   .matchs=0 },
        { .name="shmget",               .number=__NR_shmget,    .matchs=0 },
        { .name="shmat",                .number=__NR_shmat,     .matchs=0 },
        { .name="shmctl",               .number=__NR_shmctl,    .matchs=0 },
        { .name="dup",          .number=__NR_dup,       .matchs=0 },
        { .name="dup2",         .number=__NR_dup2,      .matchs=0 },
        { .name="pause",                .number=__NR_pause,     .matchs=0 },
        { .name="nanosleep",            .number=__NR_nanosleep, .matchs=0 },
        { .name="getitimer",            .number=__NR_getitimer, .matchs=0 },
        { .name="alarm",                .number=__NR_alarm,     .matchs=0 },
        { .name="setitimer",            .number=__NR_setitimer, .matchs=0 },
        { .name="getpid",               .number=__NR_getpid,    .matchs=0 },
        { .name="sendfile",             .number=__NR_sendfile,  .matchs=0 },
        { .name="socket",               .number=__NR_socket,    .matchs=0 },
        { .name="connect",              .number=__NR_connect,   .matchs=0 },
        { .name="accept",               .number=__NR_accept,    .matchs=0 },
        { .name="sendto",               .number=__NR_sendto,    .matchs=0 },
        { .name="recvfrom",             .number=__NR_recvfrom,  .matchs=0 },
        { .name="sendmsg",              .number=__NR_sendmsg,   .matchs=0 },
        { .name="recvmsg",              .number=__NR_recvmsg,   .matchs=0 },
        { .name="shutdown",             .number=__NR_shutdown,  .matchs=0 },
        { .name="bind",         .number=__NR_bind,      .matchs=0 },
        { .name="listen",               .number=__NR_listen,    .matchs=0 },
        { .name="getsockname",          .number=__NR_getsockname,       .matchs=0 },
        { .name="getpeername",          .number=__NR_getpeername,       .matchs=0 },
        { .name="socketpair",           .number=__NR_socketpair,        .matchs=0 },
        { .name="setsockopt",           .number=__NR_setsockopt,        .matchs=0 },
        { .name="getsockopt",           .number=__NR_getsockopt,        .matchs=0 },
        { .name="clone",                .number=__NR_clone,     .matchs=0 },
        { .name="fork",         .number=__NR_fork,      .matchs=0 },
        { .name="vfork",                .number=__NR_vfork,     .matchs=0 },
        { .name="execve",               .number=__NR_execve,    .matchs=0 },
        { .name="exit",         .number=__NR_exit,      .matchs=0 },
        { .name="wait4",                .number=__NR_wait4,     .matchs=0 },
        { .name="kill",         .number=__NR_kill,      .matchs=0 },
        { .name="uname",                .number=__NR_uname,     .matchs=0 },
        { .name="semget",               .number=__NR_semget,    .matchs=0 },
        { .name="semop",                .number=__NR_semop,     .matchs=0 },
        { .name="semctl",               .number=__NR_semctl,    .matchs=0 },
        { .name="shmdt",                .number=__NR_shmdt,     .matchs=0 },
        { .name="msgget",               .number=__NR_msgget,    .matchs=0 },
        { .name="msgsnd",               .number=__NR_msgsnd,    .matchs=0 },
        { .name="msgrcv",               .number=__NR_msgrcv,    .matchs=0 },
        { .name="msgctl",               .number=__NR_msgctl,    .matchs=0 },
        { .name="fcntl",                .number=__NR_fcntl,     .matchs=0 },
        { .name="flock",                .number=__NR_flock,     .matchs=0 },
        { .name="fsync",                .number=__NR_fsync,     .matchs=0 },
        { .name="fdatasync",            .number=__NR_fdatasync, .matchs=0 },
        { .name="truncate",             .number=__NR_truncate,  .matchs=0 },
        { .name="ftruncate",            .number=__NR_ftruncate, .matchs=0 },
        { .name="getdents",             .number=__NR_getdents,  .matchs=0 },
        { .name="getcwd",               .number=__NR_getcwd,    .matchs=0 },
        { .name="chdir",                .number=__NR_chdir,     .matchs=0 },
        { .name="fchdir",               .number=__NR_fchdir,    .matchs=0 },
        { .name="rename",               .number=__NR_rename,    .matchs=0 },
        { .name="mkdir",                .number=__NR_mkdir,     .matchs=0 },
        { .name="rmdir",                .number=__NR_rmdir,     .matchs=0 },
        { .name="creat",                .number=__NR_creat,     .matchs=0 },
        { .name="link",         .number=__NR_link,      .matchs=0 },
        { .name="unlink",               .number=__NR_unlink,    .matchs=0 },
        { .name="symlink",              .number=__NR_symlink,   .matchs=0 },
        { .name="symlink",              .number=__NR_symlink,   .matchs=0 },
        { .name="readlink",             .number=__NR_readlink,  .matchs=0 },
        { .name="chmod",                .number=__NR_chmod,     .matchs=0 },
        { .name="fchmod",               .number=__NR_fchmod,    .matchs=0 },
        { .name="chown",                .number=__NR_chown,     .matchs=0 },
        { .name="fchown",               .number=__NR_fchown,    .matchs=0 },
        { .name="lchown",               .number=__NR_lchown,    .matchs=0 },
        { .name="umask",                .number=__NR_umask,     .matchs=0 },
        { .name="gettimeofday",         .number=__NR_gettimeofday,      .matchs=0 },
        { .name="getrlimit",            .number=__NR_getrlimit, .matchs=0 },
        { .name="getrusage",            .number=__NR_getrusage, .matchs=0 },
        { .name="sysinfo",              .number=__NR_sysinfo,   .matchs=0 },
        { .name="times",                .number=__NR_times,     .matchs=0 },
        { .name="ptrace",               .number=__NR_ptrace,    .matchs=0 },
        { .name="getuid",               .number=__NR_getuid,    .matchs=0 },
        { .name="syslog",               .number=__NR_syslog,    .matchs=0 },
        { .name="getgid",               .number=__NR_getgid,    .matchs=0 },
        { .name="setuid",               .number=__NR_setuid,    .matchs=0 },
        { .name="setgid",               .number=__NR_setgid,    .matchs=0 },
        { .name="geteuid",              .number=__NR_geteuid,   .matchs=0 },
        { .name="getegid",              .number=__NR_getegid,   .matchs=0 },
        { .name="setpgid",              .number=__NR_setpgid,   .matchs=0 },
        { .name="getppid",              .number=__NR_getppid,   .matchs=0 },
        { .name="getpgrp",              .number=__NR_getpgrp,   .matchs=0 },
        { .name="setsid",               .number=__NR_setsid,    .matchs=0 },
        { .name="setreuid",             .number=__NR_setreuid,  .matchs=0 },
        { .name="setregid",             .number=__NR_setregid,  .matchs=0 },
        { .name="getgroups",            .number=__NR_getgroups, .matchs=0 },
        { .name="setgroups",            .number=__NR_setgroups, .matchs=0 },
        { .name="setresuid",            .number=__NR_setresuid, .matchs=0 },
        { .name="getresuid",            .number=__NR_getresuid, .matchs=0 },
        { .name="setresgid",            .number=__NR_setresgid, .matchs=0 },
        { .name="getresgid",            .number=__NR_getresgid, .matchs=0 },
        { .name="getpgid",              .number=__NR_getpgid,   .matchs=0 },
        { .name="setfsuid",             .number=__NR_setfsuid,  .matchs=0 },
        { .name="setfsgid",             .number=__NR_setfsgid,  .matchs=0 },
        { .name="getsid",               .number=__NR_getsid,    .matchs=0 },
        { .name="capget",               .number=__NR_capget,    .matchs=0 },
        { .name="capset",               .number=__NR_capset,    .matchs=0 },
        { .name="rt_sigpending",                .number=__NR_rt_sigpending,     .matchs=0 },
        { .name="rt_sigtimedwait",              .number=__NR_rt_sigtimedwait,   .matchs=0 },
        { .name="rt_sigqueueinfo",              .number=__NR_rt_sigqueueinfo,   .matchs=0 },
        { .name="rt_sigsuspend",                .number=__NR_rt_sigsuspend,     .matchs=0 },
        { .name="sigaltstack",          .number=__NR_sigaltstack,       .matchs=0 },
        { .name="utime",                .number=__NR_utime,     .matchs=0 },
        { .name="mknod",                .number=__NR_mknod,     .matchs=0 },
        { .name="uselib",               .number=__NR_uselib,    .matchs=0 },
        { .name="personality",          .number=__NR_personality,       .matchs=0 },
        { .name="ustat",                .number=__NR_ustat,     .matchs=0 },
        { .name="statfs",               .number=__NR_statfs,    .matchs=0 },
        { .name="fstatfs",              .number=__NR_fstatfs,   .matchs=0 },
        { .name="sysfs",                .number=__NR_sysfs,     .matchs=0 },
        { .name="getpriority",          .number=__NR_getpriority,       .matchs=0 },
        { .name="setpriority",          .number=__NR_setpriority,       .matchs=0 },
        { .name="sched_setparam",               .number=__NR_sched_setparam,    .matchs=0 },
        { .name="sched_getparam",               .number=__NR_sched_getparam,    .matchs=0 },
        { .name="sched_setscheduler",           .number=__NR_sched_setscheduler,        .matchs=0 },
        { .name="sched_getscheduler",           .number=__NR_sched_getscheduler,        .matchs=0 },
        { .name="sched_get_priority_max",               .number=__NR_sched_get_priority_max,    .matchs=0 },
        { .name="sched_get_priority_min",               .number=__NR_sched_get_priority_min,    .matchs=0 },
        { .name="sched_rr_get_interval",                .number=__NR_sched_rr_get_interval,     .matchs=0 },
        { .name="mlock",                .number=__NR_mlock,     .matchs=0 },
        { .name="munlock",              .number=__NR_munlock,   .matchs=0 },
        { .name="mlockall",             .number=__NR_mlockall,  .matchs=0 },
        { .name="munlockall",           .number=__NR_munlockall,        .matchs=0 },
        { .name="vhangup",              .number=__NR_vhangup,   .matchs=0 },
        { .name="modify_ldt",           .number=__NR_modify_ldt,        .matchs=0 },
        { .name="pivot_root",           .number=__NR_pivot_root,        .matchs=0 },
        { .name="_sysctl",              .number=__NR__sysctl,   .matchs=0 },
        { .name="prctl",                .number=__NR_prctl,     .matchs=0 },
        { .name="arch_prctl",           .number=__NR_arch_prctl,        .matchs=0 },
        { .name="adjtimex",             .number=__NR_adjtimex,  .matchs=0 },
        { .name="setrlimit",            .number=__NR_setrlimit, .matchs=0 },
        { .name="chroot",               .number=__NR_chroot,    .matchs=0 },
        { .name="sync",         .number=__NR_sync,      .matchs=0 },
        { .name="acct",         .number=__NR_acct,      .matchs=0 },
        { .name="settimeofday",         .number=__NR_settimeofday,      .matchs=0 },
        { .name="mount",                .number=__NR_mount,     .matchs=0 },
        { .name="umount2",              .number=__NR_umount2,   .matchs=0 },
        { .name="swapon",               .number=__NR_swapon,    .matchs=0 },
        { .name="swapoff",              .number=__NR_swapoff,   .matchs=0 },
        { .name="reboot",               .number=__NR_reboot,    .matchs=0 },
        { .name="sethostname",          .number=__NR_sethostname,       .matchs=0 },
        { .name="setdomainname",                .number=__NR_setdomainname,     .matchs=0 },
        { .name="iopl",         .number=__NR_iopl,      .matchs=0 },
        { .name="ioperm",               .number=__NR_ioperm,    .matchs=0 },
        { .name="create_module",                .number=__NR_create_module,     .matchs=0 },
        { .name="init_module",          .number=__NR_init_module,       .matchs=0 },
        { .name="delete_module",                .number=__NR_delete_module,     .matchs=0 },
        { .name="get_kernel_syms",              .number=__NR_get_kernel_syms,   .matchs=0 },
        { .name="query_module",         .number=__NR_query_module,      .matchs=0 },
        { .name="quotactl",             .number=__NR_quotactl,  .matchs=0 },
        { .name="nfsservctl",           .number=__NR_nfsservctl,        .matchs=0 },
        { .name="getpmsg",              .number=__NR_getpmsg,   .matchs=0 },
        { .name="putpmsg",              .number=__NR_putpmsg,   .matchs=0 },
        { .name="afs_syscall",          .number=__NR_afs_syscall,       .matchs=0 },
        { .name="tuxcall",              .number=__NR_tuxcall,   .matchs=0 },
        { .name="security",             .number=__NR_security,  .matchs=0 },
        { .name="gettid",               .number=__NR_gettid,    .matchs=0 },
        { .name="readahead",            .number=__NR_readahead, .matchs=0 },
        { .name="setxattr",             .number=__NR_setxattr,  .matchs=0 },
        { .name="lsetxattr",            .number=__NR_lsetxattr, .matchs=0 },
        { .name="fsetxattr",            .number=__NR_fsetxattr, .matchs=0 },
        { .name="getxattr",             .number=__NR_getxattr,  .matchs=0 },
        { .name="lgetxattr",            .number=__NR_lgetxattr, .matchs=0 },
        { .name="fgetxattr",            .number=__NR_fgetxattr, .matchs=0 },
        { .name="listxattr",            .number=__NR_listxattr, .matchs=0 },
        { .name="llistxattr",           .number=__NR_llistxattr,        .matchs=0 },
        { .name="flistxattr",           .number=__NR_flistxattr,        .matchs=0 },
        { .name="removexattr",          .number=__NR_removexattr,       .matchs=0 },
        { .name="lremovexattr",         .number=__NR_lremovexattr,      .matchs=0 },
        { .name="fremovexattr",         .number=__NR_fremovexattr,      .matchs=0 },
        { .name="tkill",                .number=__NR_tkill,     .matchs=0 },
        { .name="time",         .number=__NR_time,      .matchs=0 },
        { .name="futex",                .number=__NR_futex,     .matchs=0 },
        { .name="sched_setaffinity",            .number=__NR_sched_setaffinity, .matchs=0 },
        { .name="sched_getaffinity",            .number=__NR_sched_getaffinity, .matchs=0 },
        { .name="set_thread_area",              .number=__NR_set_thread_area,   .matchs=0 },
        { .name="io_setup",             .number=__NR_io_setup,  .matchs=0 },
        { .name="io_destroy",           .number=__NR_io_destroy,        .matchs=0 },
        { .name="io_getevents",         .number=__NR_io_getevents,      .matchs=0 },
        { .name="io_submit",            .number=__NR_io_submit, .matchs=0 },
        { .name="io_cancel",            .number=__NR_io_cancel, .matchs=0 },
        { .name="get_thread_area",              .number=__NR_get_thread_area,   .matchs=0 },
        { .name="lookup_dcookie",               .number=__NR_lookup_dcookie,    .matchs=0 },
        { .name="epoll_create",         .number=__NR_epoll_create,      .matchs=0 },
        { .name="epoll_ctl_old",                .number=__NR_epoll_ctl_old,     .matchs=0 },
        { .name="epoll_wait_old",               .number=__NR_epoll_wait_old,    .matchs=0 },
        { .name="remap_file_pages",             .number=__NR_remap_file_pages,  .matchs=0 },
        { .name="getdents64",           .number=__NR_getdents64,        .matchs=0 },
        { .name="set_tid_address",              .number=__NR_set_tid_address,   .matchs=0 },
        { .name="restart_syscall",              .number=__NR_restart_syscall,   .matchs=0 },
        { .name="semtimedop",           .number=__NR_semtimedop,        .matchs=0 },
        { .name="fadvise64",            .number=__NR_fadvise64, .matchs=0 },
        { .name="timer_create",         .number=__NR_timer_create,      .matchs=0 },
        { .name="timer_settime",                .number=__NR_timer_settime,     .matchs=0 },
        { .name="timer_gettime",                .number=__NR_timer_gettime,     .matchs=0 },
        { .name="timer_getoverrun",             .number=__NR_timer_getoverrun,  .matchs=0 },
        { .name="timer_delete",         .number=__NR_timer_delete,      .matchs=0 },
        { .name="clock_settime",                .number=__NR_clock_settime,     .matchs=0 },
        { .name="clock_gettime",                .number=__NR_clock_gettime,     .matchs=0 },
        { .name="clock_getres",         .number=__NR_clock_getres,      .matchs=0 },
        { .name="clock_nanosleep",              .number=__NR_clock_nanosleep,   .matchs=0 },
        { .name="exit_group",           .number=__NR_exit_group,        .matchs=0 },
        { .name="epoll_wait",           .number=__NR_epoll_wait,        .matchs=0 },
        { .name="epoll_ctl",            .number=__NR_epoll_ctl, .matchs=0 },
        { .name="tgkill",               .number=__NR_tgkill,    .matchs=0 },
        { .name="utimes",               .number=__NR_utimes,    .matchs=0 },
        { .name="vserver",              .number=__NR_vserver,   .matchs=0 },
        { .name="mbind",                .number=__NR_mbind,     .matchs=0 },
        { .name="set_mempolicy",                .number=__NR_set_mempolicy,     .matchs=0 },
        { .name="get_mempolicy",                .number=__NR_get_mempolicy,     .matchs=0 },
        { .name="mq_open",              .number=__NR_mq_open,   .matchs=0 },
        { .name="mq_unlink",            .number=__NR_mq_unlink, .matchs=0 },
        { .name="mq_timedsend",         .number=__NR_mq_timedsend,      .matchs=0 },
        { .name="mq_timedreceive",              .number=__NR_mq_timedreceive,   .matchs=0 },
        { .name="mq_notify",            .number=__NR_mq_notify, .matchs=0 },
        { .name="mq_getsetattr",                .number=__NR_mq_getsetattr,     .matchs=0 },
        { .name="kexec_load",           .number=__NR_kexec_load,        .matchs=0 },
        { .name="waitid",               .number=__NR_waitid,    .matchs=0 },
        { .name="add_key",              .number=__NR_add_key,   .matchs=0 },
        { .name="request_key",          .number=__NR_request_key,       .matchs=0 },
        { .name="keyctl",               .number=__NR_keyctl,    .matchs=0 },
        { .name="ioprio_set",           .number=__NR_ioprio_set,        .matchs=0 },
        { .name="ioprio_get",           .number=__NR_ioprio_get,        .matchs=0 },
        { .name="inotify_init",         .number=__NR_inotify_init,      .matchs=0 },
        { .name="inotify_add_watch",            .number=__NR_inotify_add_watch, .matchs=0 },
        { .name="inotify_rm_watch",             .number=__NR_inotify_rm_watch,  .matchs=0 },
        { .name="migrate_pages",                .number=__NR_migrate_pages,     .matchs=0 },
        { .name="openat",               .number=__NR_openat,    .matchs=0 },
        { .name="mkdirat",              .number=__NR_mkdirat,   .matchs=0 },
        { .name="mknodat",              .number=__NR_mknodat,   .matchs=0 },
        { .name="fchownat",             .number=__NR_fchownat,  .matchs=0 },
        { .name="futimesat",            .number=__NR_futimesat, .matchs=0 },
        { .name="newfstatat",           .number=__NR_newfstatat,        .matchs=0 },
        { .name="unlinkat",             .number=__NR_unlinkat,  .matchs=0 },
        { .name="renameat",             .number=__NR_renameat,  .matchs=0 },
        { .name="linkat",               .number=__NR_linkat,    .matchs=0 },
        { .name="symlinkat",            .number=__NR_symlinkat, .matchs=0 },
        { .name="readlinkat",           .number=__NR_readlinkat,        .matchs=0 },
        { .name="fchmodat",             .number=__NR_fchmodat,  .matchs=0 },
        { .name="faccessat",            .number=__NR_faccessat, .matchs=0 },
        { .name="pselect6",             .number=__NR_pselect6,  .matchs=0 },
        { .name="ppoll",                .number=__NR_ppoll,     .matchs=0 },
        { .name="unshare",              .number=__NR_unshare,   .matchs=0 },
        { .name="set_robust_list",              .number=__NR_set_robust_list,   .matchs=0 },
        { .name="get_robust_list",              .number=__NR_get_robust_list,   .matchs=0 },
        { .name="splice",               .number=__NR_splice,    .matchs=0 },
        { .name="tee",          .number=__NR_tee,       .matchs=0 },
        { .name="sync_file_range",              .number=__NR_sync_file_range,   .matchs=0 },
        { .name="vmsplice",             .number=__NR_vmsplice,  .matchs=0 },
        { .name="move_pages",           .number=__NR_move_pages,        .matchs=0 },
        { .name="utimensat",            .number=__NR_utimensat, .matchs=0 },
        { .name="ORE_getcpu",           .number=__IGNORE_getcpu,        .matchs=0 },
        { .name="epoll_pwait",          .number=__NR_epoll_pwait,       .matchs=0 },
        { .name="signalfd",             .number=__NR_signalfd,  .matchs=0 },
        { .name="timerfd_create",               .number=__NR_timerfd_create,    .matchs=0 },
        { .name="eventfd",              .number=__NR_eventfd,   .matchs=0 },
        { .name="fallocate",            .number=__NR_fallocate, .matchs=0 },
        { .name="timerfd_settime",              .number=__NR_timerfd_settime,   .matchs=0 },
        { .name="timerfd_gettime",              .number=__NR_timerfd_gettime,   .matchs=0 },
        { .name="accept4",              .number=__NR_accept4,   .matchs=0 },
        { .name="signalfd4",            .number=__NR_signalfd4, .matchs=0 },
        { .name="eventfd2",             .number=__NR_eventfd2,  .matchs=0 },
        { .name="epoll_create1",                .number=__NR_epoll_create1,     .matchs=0 },
        { .name="dup3",         .number=__NR_dup3,      .matchs=0 },
        { .name="pipe2",                .number=__NR_pipe2,     .matchs=0 },
        { .name="inotify_init1",                .number=__NR_inotify_init1,     .matchs=0 },
        { .name="preadv",               .number=__NR_preadv,    .matchs=0 },
        { .name="pwritev",              .number=__NR_pwritev,   .matchs=0 },
        { .name="rt_tgsigqueueinfo",            .number=__NR_rt_tgsigqueueinfo, .matchs=0 },
        { .name="perf_event_open",              .number=__NR_perf_event_open,   .matchs=0 },
	{},
};

#else // 32 bits architecture

#define MAX_I32_SYSCALLS 299
#define MAX_SYSCALLS MAX_I32_SYSCALLS

char *syscallnames[] = {
	"ni_syscall-1",
	"exit",
	"fork",
	"read",
	"write",
	"open",             /* 5 */
	"close",
	"waitpid",
	"creat",
	"link",
	"unlink",           /* 10 */
	"execve",
	"chdir",
	"time",
	"mknod",
	"chmod",            /* 15 */
	"lchown16",
	"ni_syscall-2",                       /* old break syscall holder */
	"stat",
	"lseek",
	"getpid",           /* 20 */
	"mount",
	"oldumount",
	"setuid16",
	"getuid16",
	"stime",            /* 25 */
	"ptrace",
	"alarm",
	"fstat",
	"pause",
	"utime",            /* 30 */
	"ni_syscall-3",       /* old stty syscall holder */
	"ni_syscall-4",       /* old gtty syscall holder */
	"access",
	"nice",
	"ni_syscall-5",       /* 35 */   /* old ftime syscall holder */
	"sync",
	"kill",
	"rename",
	"mkdir",
	"rmdir",            /* 40 */
	"dup",
	"pipe",
	"times",
	"ni_syscall-6",       /* old prof syscall holder */
	"brk",              /* 45 */
	"setgid16",
	"getgid16",
	"signal",
	"geteuid16",
	"getegid16",        /* 50 */
	"acct",
	"umount",           /* recycled never used phys() */
	"ni_syscall-7",       /* old lock syscall holder */
	"ioctl",
	"fcntl",            /* 55 */
	"ni_syscall-8",       /* old mpx syscall holder */
	"setpgid",
	"ni_syscall-9",       /* old ulimit syscall holder */
	"olduname",
	"umask",            /* 60 */
	"chroot",
	"ustat",
	"dup2",
	"getppid",
	"getpgrp",          /* 65 */
	"setsid",
	"sigaction",
	"sgetmask",
	"ssetmask",
	"setreuid16",       /* 70 */
	"setregid16",
	"sigsuspend",
	"sigpending",
	"sethostname",
	"setrlimit",        /* 75 */
	"old_getrlimit",
	"getrusage",
	"gettimeofday",
	"settimeofday",
	"getgroups16",      /* 80 */
	"setgroups16",
	"old_select",
	"symlink",
	"lstat",
	"readlink",         /* 85 */
	"uselib",
	"swapon",
	"reboot",
	"old_readdir",
	"old_mmap",             /* 90 */
	"munmap",
	"truncate",
	"ftruncate",
	"fchmod",
	"fchown16",         /* 95 */
	"getpriority",
	"setpriority",
	"ni_syscall-10",       /* old profil syscall holder */
	"statfs",
	"fstatfs",          /* 100 */
	"ioperm",
	"socketcall",
	"syslog",
	"setitimer",
	"getitimer",        /* 105 */
	"newstat",
	"newlstat",
	"newfstat",
	"uname",
	"iopl",             /* 110 */
	"vhangup",
	"ni_syscall-11",       /* old "idle" system call */
	"vm86old",
	"wait4",
	"swapoff",          /* 115 */
	"sysinfo",
	"ipc",
	"fsync",
	"sigreturn",
	"clone",            /* 120 */
	"setdomainname",
	"newuname",
	"modify_ldt",
	"adjtimex",
	"mprotect",         /* 125 */
	"sigprocmask",
	"create_module",
	"init_module",
	"delete_module",
	"get_kernel_syms",  /* 130 */
	"quotactl",
	"getpgid",
	"fchdir",
	"bdflush",
	"sysfs",            /* 135 */
	"personality",
	"ni_syscall-12",       /* for afs_syscall */
	"setfsuid16",
	"setfsgid16",
	"llseek",           /* 140 */
	"getdents",
	"select",
	"flock",
	"msync",
	"readv",            /* 145 */
	"writev",
	"getsid",
	"fdatasync",
	"sysctl",
	"mlock",            /* 150 */
	"munlock",
	"mlockall",
	"munlockall",
	"sched_setparam",
	"sched_getparam",   /* 155 */
	"sched_setscheduler",
	"sched_getscheduler",
	"sched_yield",
	"sched_get_priority_max",
	"sched_get_priority_min",  /* 160 */
	"sched_rr_get_interval",
	"nanosleep",
	"mremap",
	"setresuid16",
	"getresuid16",      /* 165 */
	"vm86",
	"query_module",
	"poll",
	"nfsservctl",
	"setresgid16",      /* 170 */
	"getresgid16",
	"prctl",
	"rt_sigreturn",
	"rt_sigaction",
	"rt_sigprocmask",   /* 175 */
	"rt_sigpending",
	"rt_sigtimedwait",
	"rt_sigqueueinfo",
	"rt_sigsuspend",
	"pread",            /* 180 */
	"pwrite",
	"chown16",
	"getcwd",
	"capget",
	"capset",           /* 185 */
	"sigaltstack",
	"sendfile",
	"ni_syscall-13",       /* streams1 */
	"ni_syscall-14",       /* streams2 */
	"vfork",            /* 190 */
	"getrlimit",
	"mmap2",
	"truncate64",
	"ftruncate64",
	"stat64",           /* 195 */
	"lstat64",
	"fstat64",
	"lchown",
	"getuid",
	"getgid",           /* 200 */
	"geteuid",
	"getegid",
	"setreuid",
	"setregid",
	"getgroups",        /* 205 */
	"setgroups",
	"fchown",
	"setresuid",
	"getresuid",
	"setresgid",        /* 210 */
	"getresgid",
	"chown",
	"setuid",
	"setgid",
	"setfsuid",         /* 215 */
	"setfsgid",
	"pivot_root",
	"mincore",
	"madvise",
	"getdents64",       /* 220 */
	"fcntl64",
	"ni_syscall-15",       /* reserved for TUX */
	"ni_syscall-16",       /* Reserved for Security */
	"gettid",
	"readahead",        /* 225 */
	"setxattr",       /* reserved for setxattr */
	"lsetxattr",       /* reserved for lsetxattr */
	"fsetxattr",       /* reserved for fsetxattr */
	"getxattr",       /* reserved for getxattr */
	"lgetxattr",       /* 230 reserved for lgetxattr */
	"fgetxattr",       /* reserved for fgetxattr */
	"listxattr",       /* reserved for listxattr */
	"llistxattr",       /* reserved for llistxattr */
	"flistxattr",       /* reserved for flistxattr */
	"removexattr",       /* 235 reserved for removexattr */
	"lremovexattr",       /* reserved for lremovexattr */
	"fremovexattr",       /* reserved for fremovexattr */
	"tkill",
	"sendfile64",
        "futex",         /* 240 */
        "sched_setaffinity",
        "sched_getaffinity",
        "set_thread_area",
        "get_thread_area",
        "io_setup",      /* 245 */
        "io_destroy",
        "io_getevents",
        "io_submit",
        "io_cancel",
        "fadvise64",     /* 250 */
        "ni_syscall",
        "exit_group",
        "lookup_dcookie",
        "epoll_create",
        "epoll_ctl",     /* 255 */
        "epoll_wait",
        "remap_file_pages",
        "set_tid_address",
        "timer_create",
        "timer_settime",         /* 260 */
        "timer_gettime",
        "timer_getoverrun",
        "timer_delete",
        "clock_settime",
        "clock_gettime",         /* 265 */
        "clock_getres",
        "clock_nanosleep",
        "statfs64",
        "fstatfs64",     
        "tgkill",        /* 270 */
        "utimes",
        "fadvise64_64",
        "ni_syscall",    /* sys_vserver */
        "mbind",
        "get_mempolicy",
        "set_mempolicy",
        "mq_open",
        "mq_unlink",
        "mq_timedsend",
        "mq_timedreceive",       /* 280 */
        "mq_notify",
        "mq_getsetattr",
        "ni_syscall",            /* reserved for kexec */
        "waitid",
        "ni_syscall",            /* 285 */ /* available */
        "add_key",
        "request_key",
        "keyctl",
	"ni_syscall-31",
	"ni_syscall-32",	 /* 290 */
	"ni_syscall-33",
	"ni_syscall-34",
	"ni_syscall-35",
	"ni_syscall-36",
	"ni_syscall-37",	 /* 295 */
	"ni_syscall-38",
	"ni_syscall-39",
	"ni_syscall-40",
	"ni_syscall-41",
	NULL			 /* sentinel */
};

#endif // __LINUX__
#endif

