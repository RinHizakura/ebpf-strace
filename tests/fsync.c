#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *path = "/tmp/test_fsync";
    int fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        ret = -1;
        goto end;
    }
    if (fsync(fd) < 0) {
        ret = -1;
        goto end;
    }
    printf("fsync(%d) = 0\n", fd);
end:
    if (fd >= 0)
        close(fd);
    unlink(path);
    puts("+++ exited with 0 +++");
    return ret;
}
