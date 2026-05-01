#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *path = "/tmp/test_ftruncate";
    int fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        ret = -1;
        goto end;
    }
    if (ftruncate(fd, 0) < 0) {
        ret = -1;
        goto end;
    }
    printf("ftruncate(%d, 0) = 0\n", fd);
end:
    if (fd >= 0)
        close(fd);
    unlink(path);
    puts("+++ exited with 0 +++");
    return ret;
}
