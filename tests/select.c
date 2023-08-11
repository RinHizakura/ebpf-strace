#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <unistd.h>

#define xsnprintf(pos, buf, sz, format, ...) \
    (pos) += snprintf((buf) + (pos), (sz) - (pos), format, ##__VA_ARGS__);

static char *build_fds(int *sets, int set_cnt, fd_set *fds)
{
#define FDS_BUF_SIZE 512
    static char buf[FDS_BUF_SIZE];

    int pos = 0;

    FD_ZERO(fds);

    xsnprintf(pos, buf, FDS_BUF_SIZE, "[");
    for (int i = 0; i < set_cnt; i++) {
        FD_SET(sets[i], fds);
        if (i != 0)
            xsnprintf(pos, buf, FDS_BUF_SIZE, " ");
        xsnprintf(pos, buf, FDS_BUF_SIZE, "%d", sets[i]);
    }
    xsnprintf(pos, buf, FDS_BUF_SIZE, "]");

    return buf;
}

static char *build_timeval(long tv_sec, long tv_usec, struct timeval *tv)
{
#define TIMEVAL_BUF_SIZE 512
    static char buf[TIMEVAL_BUF_SIZE];

    int pos = 0;

    tv->tv_sec = tv_sec;
    tv->tv_usec = tv_usec;

    xsnprintf(pos, buf, TIMEVAL_BUF_SIZE, "{tv_sec=%ld, tv_usec=%ld}", tv_sec,
              tv_usec);

    return buf;
}

int main()
{
    int ret = 0;

    int sets[2] = {0, 2};
    fd_set rfds;
    char *fds_str = build_fds(sets, 2, &rfds);

    struct timeval tv;
    char *tv_str = build_timeval(1, 0, &tv);

    int nfds = 3;
    long result = syscall(SYS_select, nfds, &rfds, NULL, NULL, &tv);
    if (result == -1) {
        ret = -1;
        goto end;
    }
    printf("select(%d, %s, NULL, NULL, %s) = %ld\n", nfds, fds_str, tv_str,
           result);

end:
    puts("+++ exited with 0 +++");
    return ret;
}
