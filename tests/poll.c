#include <poll.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    struct pollfd pfd;
    pfd.fd = STDIN_FILENO;
    pfd.events = POLLIN;

    int ret = poll(&pfd, 1, 0);
    printf("poll([{fd=%d, events=POLLIN}], 1, 0) = %d\n", STDIN_FILENO, ret);

    puts("+++ exited with 0 +++");
    return 0;
}
