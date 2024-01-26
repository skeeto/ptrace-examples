#define _POSIX_C_SOURCE 200112L

/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>

/* Linux */
#include <syscall.h>
#include <sys/reg.h>
#include <sys/ptrace.h>

#include "xpledge.h"

#define FATAL(...) \
    do { \
        fprintf(stderr, "strace: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

static char blocked_syscalls[SYS_xpledge + 1];

static int
is_syscall_blocked(int syscall)
{
    if (syscall < 0 || syscall >= (int)sizeof(blocked_syscalls))
        return 0;
    return blocked_syscalls[syscall];
}

static long
set_xpledge(int kinds)
{
    memset(blocked_syscalls, 1, sizeof(blocked_syscalls));
    blocked_syscalls[SYS_brk] = 0;
    blocked_syscalls[SYS_mmap] = 0;
    blocked_syscalls[SYS_munmap] = 0;
    blocked_syscalls[SYS_close] = 0;
    blocked_syscalls[SYS_exit] = 0;
    blocked_syscalls[SYS_exit_group] = 0;

    if (kinds & XPLEDGE_RDWR) {
        blocked_syscalls[SYS_read] = 0;
        blocked_syscalls[SYS_pread64] = 0;
        blocked_syscalls[SYS_readv] = 0;
        blocked_syscalls[SYS_preadv] = 0;
        blocked_syscalls[SYS_write] = 0;
        blocked_syscalls[SYS_pwrite64] = 0;
        blocked_syscalls[SYS_writev] = 0;
        blocked_syscalls[SYS_pwritev] = 0;
    }

    if (kinds & XPLEDGE_OPEN) {
        blocked_syscalls[SYS_open] = 0;
    }

    return 0;
}

const int long_size = sizeof(long);
void getdata(pid_t child, long addr,
             void *str, int len)
{   void *laddr;
    int i, j;
    union u {
            long val;
            void* chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        data.val = ptrace(PTRACE_PEEKDATA,
                          child, addr + i * 4,
                          NULL);
        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        data.val = ptrace(PTRACE_PEEKDATA,
                          child, addr + i * 4,
                          NULL);
        memcpy(laddr, data.chars, j);
    }
}
void putdata(pid_t child, long addr,
             void *str, int len)
{   void *laddr;
    int i, j;
    union u {
            long val;
            void* chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * 4, data.val);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * 4, data.val);
    }
}

static int
handle_aux_magic01(pid_t pid, struct user_regs_struct regs) {
    long arg1_raw = regs.rdi;
    long arg2_raw = regs.rsi;
    struct aux_magic01a a;
    struct aux_magic01b b;
    // TODO: Read and write to the process memory directly (e.g. using /proc/pid/mem) so it's faster
    getdata(pid, arg1_raw, &a, sizeof(a));
    getdata(pid, arg2_raw, &b, sizeof(b));
    if (a.y != b.y) return -EINVAL;
    a.xplusy = a.x + a.y;
    b.yminusz = b.y - b.z;
    putdata(pid, arg1_raw, &a, sizeof(a));
    putdata(pid, arg2_raw, &b, sizeof(b));
}

int
main(int argc, char **argv)
{
    if (argc <= 1)
        FATAL("too few arguments: %d", argc);

    pid_t pid = fork();
    switch (pid) {
        case -1: /* error */
            FATAL("%s", strerror(errno));
        case 0:  /* child */
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            /* Because we're now a tracee, execvp will block until the parent
             * attaches and allows us to continue. */
            execvp(argv[1], argv + 1);
            FATAL("%s", strerror(errno));
    }

    /* parent */
    waitpid(pid, 0, 0); // sync with execvp
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    for (;;) {
        /* Enter next system call */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
            FATAL("%s", strerror(errno));
        }
        if (waitpid(pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));

        /* Gather system call arguments */
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            FATAL("%s", strerror(errno));

        if (is_syscall_blocked(regs.orig_rax)) {
            regs.orig_rax = SYS_blocked; // set to invalid system call
            if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
                FATAL("%s", strerror(errno));
        }

        /* Run system call and stop on exit */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));

        /* Special handling per system call (entrance) */
        fprintf(stdout, "Got syscall number=%llu\n", regs.orig_rax);
        switch (regs.orig_rax) {
            case SYS_exit:
                exit(regs.rdi);
            case SYS_exit_group:
                exit(regs.rdi);
            case SYS_xpledge:
                regs.rax = set_xpledge(regs.rdi);
                break;
            case SYS_aux_magic01:
                regs.rax = handle_aux_magic01(pid, regs);
                break;
        }

        /* Special handling per system call (exit) */
        switch (regs.orig_rax) {
            case SYS_blocked:
                regs.rax = -EPERM;
                if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
                    FATAL("%s", strerror(errno));
                break;
            case SYS_xpledge:
            case SYS_aux_magic01:
                if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
                    FATAL("%s", strerror(errno));
                break;
        }
    }
}
