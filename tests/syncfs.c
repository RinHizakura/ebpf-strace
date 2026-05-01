#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    int fd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        ret = -1;
        goto end;
    }
    if (syncfs(fd) < 0) {
        ret = -1;
        goto end;
    }
    printf("syncfs(%d) = 0\n", fd);
end:
    if (fd >= 0)
        close(fd);
    puts("+++ exited with 0 +++");
    return ret;
}
