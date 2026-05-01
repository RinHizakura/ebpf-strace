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
    printf(
        "epoll_ctl(%d, EPOLL_CTL_ADD, %d, {events=EPOLLIN, data={u64=0x%x}}) = "
        "0\n",
        epfd, pipefd[0], (unsigned) pipefd[0]);
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
