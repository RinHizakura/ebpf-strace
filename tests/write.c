#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *path = "/tmp/test_write_data";
    int fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        ret = -1;
        goto end;
    }
    ssize_t n = write(fd, "hello", 5);
    if (n < 0) {
        ret = -1;
        goto end;
    }
    printf("write(%d, \"hello\", 5) = %zd\n", fd, n);
end:
    if (fd >= 0)
        close(fd);
    unlink(path);
    puts("+++ exited with 0 +++");
    return ret;
}
