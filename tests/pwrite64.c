#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *path = "/tmp/test_pwrite64_data";
    int fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        ret = -1;
        goto end;
    }
    ssize_t n = pwrite(fd, "hello", 5, 0);
    if (n < 0) {
        ret = -1;
        goto end;
    }
    printf("pwrite64(%d, \"hello\", 5, 0) = %zd\n", fd, n);
end:
    if (fd >= 0)
        close(fd);
    unlink(path);
    puts("+++ exited with 0 +++");
    return ret;
}
