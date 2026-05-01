#include <fcntl.h>
#include <stdio.h>
#include <sys/uio.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *path = "/tmp/test_readv_data";
    int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0) {
        ret = -1;
        goto end;
    }
    if (write(fd, "hello", 5) != 5) {
        ret = -1;
        goto end;
    }
    lseek(fd, 0, SEEK_SET);
    char buf[6];
    struct iovec iov = {.iov_base = buf, .iov_len = 5};
    ssize_t n = readv(fd, &iov, 1);
    if (n < 0 || n > 5) {
        ret = -1;
        goto end;
    }
    buf[n] = '\0';
    printf("readv(%d, [{iov_base=\"%s\", iov_len=5}], 1) = %zd\n", fd, buf, n);
end:
    if (fd >= 0)
        close(fd);
    unlink(path);
    puts("+++ exited with 0 +++");
    return ret;
}
