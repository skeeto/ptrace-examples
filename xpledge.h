#ifndef PLEDGE_H
#define PLEDGE_H

#define _GNU_SOURCE
#include <unistd.h>

#define SYS_xpledge 10000

#define XPLEDGE_RDWR  (1 << 0)
#define XPLEDGE_OPEN  (1 << 1)

#define xpledge(arg) syscall(SYS_xpledge, arg)

#define xpledge(arg) syscall(SYS_xpledge, arg)

#define SYS_aux_magic01 10001

struct aux_magic01a {
    int x;
    int y;
    int xplusy;
};

struct aux_magic01b {
    int y;
    int z;
    int yminusz;
};

#define auxsys_magic01(arg1, arg2) syscall(SYS_aux_magic01, arg1, arg2)

#endif
