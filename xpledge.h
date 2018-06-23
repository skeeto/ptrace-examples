#ifndef PLEDGE_H
#define PLEDGE_H

#define _GNU_SOURCE
#include <unistd.h>

#define SYS_xpledge 10000

#define XPLEDGE_RDWR  (1 << 0)
#define XPLEDGE_OPEN  (1 << 1)

#define xpledge(arg) syscall(SYS_xpledge, arg)

#endif
