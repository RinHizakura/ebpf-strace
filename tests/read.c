#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *path = "/tmp/test_read_data";
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
    char buf[16];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 0) {
        ret = -1;
        goto end;
    }
    buf[n] = '\0';
    printf("read(%d, \"%s\", %zu) = %zd\n", fd, buf, sizeof(buf), n);
end:
    if (fd >= 0)
        close(fd);
    unlink(path);
    puts("+++ exited with 0 +++");
    return ret;
}
