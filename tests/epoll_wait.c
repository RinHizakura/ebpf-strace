#include <stdio.h>
#include <sys/epoll.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        ret = -1;
        goto end;
    }
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        ret = -1;
        goto end;
    }
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = pipefd[0];
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev) < 0) {
        ret = -1;
        goto end;
    }
    write(pipefd[1], "x", 1);
    struct epoll_event events[10];
    int n = epoll_wait(epfd, events, 10, 0);
    if (n < 0) {
        ret = -1;
        goto end;
    }
    printf("epoll_wait(%d, [], 10, 0) = %d\n", epfd, n);
end:
    if (epfd >= 0)
        close(epfd);
    if (pipefd[0] >= 0)
        close(pipefd[0]);
    if (pipefd[1] >= 0)
        close(pipefd[1]);
    puts("+++ exited with 0 +++");
    return ret;
}
