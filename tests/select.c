#include <stdlib.h>
#include <sys/select.h>
#include <sys/syscall.h>

int do_select()
{
    fd_set rfds;
    struct timeval tv;

    FD_ZERO(&rfds);
    FD_SET(0, &rfds);

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    syscall(SYS_select, 1, &rfds, NULL, NULL, &tv);

    return 0;
}
