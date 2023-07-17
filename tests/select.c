#include <stdlib.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <unistd.h>

int do_select()
{
    fd_set rfds;
    struct timeval tv;

    FD_ZERO(&rfds);
    FD_SET(0, &rfds);
    FD_SET(1, &rfds);
    FD_SET(2, &rfds);

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    syscall(SYS_select, 3, &rfds, NULL, NULL, &tv);

    return 0;
}
