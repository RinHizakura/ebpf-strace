#include <sys/syscall.h>
#include <unistd.h>

int do_pipe()
{
    int pipefd[2];

    if (syscall(SYS_pipe, pipefd) == -1)
        return -1;

    close(pipefd[0]);
    close(pipefd[1]);
    return 0;
}
