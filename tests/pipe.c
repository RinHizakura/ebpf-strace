#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    int pipefd[2];

    long result = syscall(SYS_pipe, pipefd);
    if (result == -1) {
        ret = -1;
        goto end;
    }
    printf("pipe([%d,%d]) = %d\n", pipefd[0], pipefd[1], ret);
    close(pipefd[0]);
    close(pipefd[1]);

end:
    puts("+++ exited with 0 +++");
    return ret;
}
