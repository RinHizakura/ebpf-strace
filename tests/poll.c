#include <poll.h>
#include <unistd.h>

int do_poll()
{
    struct pollfd pfd;
    pfd.fd = STDIN_FILENO;
    pfd.events = POLLIN;

    poll(&pfd, 1, 0);

    return 0;
}
