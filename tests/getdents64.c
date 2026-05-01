#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    int fd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        ret = -1;
        goto end;
    }
    char buf[4096];
    size_t count = sizeof(buf);
    long n = syscall(SYS_getdents64, fd, buf, count);
    if (n < 0) {
        ret = -1;
        goto end;
    }
    printf("getdents64(%d, %zu) = %ld\n", fd, count, n);
end:
    if (fd >= 0)
        close(fd);
    puts("+++ exited with 0 +++");
    return ret;
}
