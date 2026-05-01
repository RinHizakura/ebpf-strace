#include <fcntl.h>
#include <stdio.h>
#include <sys/uio.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *path = "/tmp/test_writev_data";
    int fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        ret = -1;
        goto end;
    }
    const char *data = "hello";
    struct iovec iov = {.iov_base = (void *) data, .iov_len = 5};
    ssize_t n = writev(fd, &iov, 1);
    if (n < 0) {
        ret = -1;
        goto end;
    }
    printf("writev(%d, [{iov_base=\"hello\", iov_len=5}], 1) = %zd\n", fd, n);
end:
    if (fd >= 0)
        close(fd);
    unlink(path);
    puts("+++ exited with 0 +++");
    return ret;
}
