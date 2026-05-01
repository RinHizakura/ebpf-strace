#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        ret = -1;
        goto end;
    }
    int newfd = pipefd[1] + 1;
    int r = dup3(pipefd[0], newfd, O_CLOEXEC);
    if (r < 0) {
        ret = -1;
        goto end;
    }
    printf("dup3(%d, %d, O_CLOEXEC) = %d\n", pipefd[0], newfd, r);
    close(r);
end:
    if (pipefd[0] >= 0)
        close(pipefd[0]);
    if (pipefd[1] >= 0)
        close(pipefd[1]);
    puts("+++ exited with 0 +++");
    return ret;
}
