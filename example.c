#include "xpledge.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(void)
{
    // Test aux_magic syscalls
    struct aux_magic01a m01a = {.x=1, .y=4, .xplusy=0};
    struct aux_magic01b m01b = {.y=4, .z=2, .yminusz=0};
    if (auxsys_magic01(&m01a, &m01b) == -1) printf("auxsys_magic01 failed, err=%s\n", strerror(errno));
    else printf("auxsys_magic01 succeeded, m01a.xplusy=%d, m01b.yminusz=%d\n", m01a.xplusy, m01b.yminusz);

    unsigned x;

    /* Open /dev/urandom, which should succeed */
    FILE *urandom = fopen("/dev/urandom", "r");
    if (!urandom) {
        printf("open(\"/dev/urandom\")[1], err=%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    } else {
        printf("open(\"/dev/urandom\")[1], fd=%d\n", urandom->_fileno);
    }

    /* Demonstrate a read */
    x = 0;
    fread(&x, sizeof(x), 1, urandom);
    printf("fread(\"/dev/urandom\")[1], x=%u\n", x);

    /* Pledge to no longer open files */
    if (xpledge(XPLEDGE_RDWR) == -1)
        printf("xpledge failed: %s\n", strerror(errno));
    else
        puts("xpledged to no longer open files");

    /* Try to open /dev/urandom a second time */
    FILE *urandom2 = fopen("/dev/urandom", "r");
    if (!urandom2) {
        printf("fopen(\"/dev/urandom\")[2], err=%s\n", strerror(errno));
    } else {
        printf("open(\"/dev/urandom\")[2], fd=%d\n", urandom2->_fileno);
    }
    if (urandom2) {
        /* Prove we can read from it */
        x = 0;
        fread(&x, sizeof(x), 1, urandom2);
        printf("fread(\"/dev/urandom\")[2], x=%u\n", x);
    } else {
        printf("skipped fread(\"/dev/urandom\")[2]\n");
    }

    /* Should still be able to read from first /dev/urandom handle */
    x = 0;
    fread(&x, sizeof(x), 1, urandom);
    printf("fread(\"/dev/urandom\")[1], x=%u\n",x);

    if (urandom2)
        fclose(urandom2);
    fclose(urandom);
}
