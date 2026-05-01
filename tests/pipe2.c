#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    int fds[2];
    if (pipe2(fds, 0) < 0)
        goto end;
    printf("pipe2([%d, %d], 0) = 0\n", fds[0], fds[1]);
    close(fds[0]);
    close(fds[1]);
end:
    puts("+++ exited with 0 +++");
    return 0;
}
