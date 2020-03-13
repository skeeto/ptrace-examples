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
            regs.orig_rax = -1; // set to invalid system call
            if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
                FATAL("%s", strerror(errno));
        }

        /* Special handling per system call (entrance) */
        switch (regs.orig_rax) {
            case SYS_exit:
                exit(regs.rdi);
            case SYS_exit_group:
                exit(regs.rdi);
            case SYS_xpledge:
                set_xpledge(regs.rdi);
                break;
        }

        /* Run system call and stop on exit */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));

        /* Special handling per system call (exit) */
        switch (regs.orig_rax) {
            case -1:
                if (ptrace(PTRACE_POKEUSER, pid, RAX * 8, -EPERM) == -1)
                    FATAL("%s", strerror(errno));
                break;
            case SYS_xpledge:
                if (ptrace(PTRACE_POKEUSER, pid, RAX * 8, 0) == -1)
                    FATAL("%s", strerror(errno));
                break;
        }
    }
}
