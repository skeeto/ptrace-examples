# Linux PTrace examples

Full article: [Intercepting and Emulating Linux System Calls with Ptrace][full]

```
$ gcc xpledge.c -o xpledge && gcc example.c -o example && ./xpledge ./example
auxsys_magic01 succeeded, m01a.xplusy=4, m01b.yminusz=2
open("/dev/urandom")[1], fd=3
fread("/dev/urandom")[1], x=1547198313
xpledged to no longer open files
fopen("/dev/urandom")[2], err=Operation not permitted
skipped fread("/dev/urandom")[2]
fread("/dev/urandom")[1], x=1332445985

$ gcc example.c -o example && ./example
auxsys_magic01 failed, err=Function not implemented
open("/dev/urandom")[1], fd=3
fread("/dev/urandom")[1], x=3814369549
xpledge failed: Function not implemented
open("/dev/urandom")[2], fd=4
fread("/dev/urandom")[2], x=2897060695
fread("/dev/urandom")[1], x=2685374535
```

See also https://github.com/phucvin/test-virtualization/blob/main/ptrace02/notes.md

TODO:
- In xpledge.c, read and write to the process memory directly (e.g. using /proc/pid/mem) so it's faster

[full]: http://nullprogram.com/blog/2018/06/23/
