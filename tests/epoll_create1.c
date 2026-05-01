#include <stdio.h>
#include <sys/epoll.h>
#include <unistd.h>

int main()
{
    int epfd = epoll_create1(0);
    if (epfd < 0)
        goto end;
    printf("epoll_create1(0) = %d\n", epfd);
    close(epfd);
end:
    puts("+++ exited with 0 +++");
    return 0;
}
