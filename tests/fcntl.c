#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *path = "/tmp/test_fcntl";

    int fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        ret = -1;
        goto end;
    }

    int flags = fcntl(fd, F_GETFD);
    if (flags < 0) {
        ret = -1;
        goto end;
    }
    printf("fcntl(%d, F_GETFD, 0x0) = %d\n", fd, flags);

    int r = fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (r < 0) {
        ret = -1;
        goto end;
    }
    printf("fcntl(%d, F_SETFD, 0x1) = %d\n", fd, r);

end:
    if (fd >= 0)
        close(fd);
    unlink(path);
    puts("+++ exited with 0 +++");
    return ret;
}
