#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main()
{
    const char *dir = "tests";
    int dirfd = syscall(SYS_open, dir, O_DIRECTORY);
    if (dirfd < 0)
        return -1;
    printf("open(\"%s\", O_DIRECTORY) = %d\n", dir, dirfd);
    close(dirfd);

    const char *tmpfile = "/tmp/tmpfile";
    int mode = 0400;
    int fd = syscall(SYS_open, tmpfile, O_CREAT, mode);
    if (fd < 0)
        return -1;
    printf("open(\"%s\", O_CREAT, 0%o) = %d\n", tmpfile, mode, fd);
    close(fd);

    fd = syscall(SYS_open, tmpfile, O_RDONLY);
    if (fd < 0)
        return -1;
    printf("open(\"%s\", O_RDONLY) = %d\n", tmpfile, fd);
    close(fd);

    fd = syscall(SYS_open, tmpfile, O_WRONLY | O_NONBLOCK | 0x80000000);
    if (fd < 0)
        return -1;
    printf("open(\"%s\", O_WRONLY|O_NONBLOCK|0x80000000) = %d\n", tmpfile, fd);
    close(fd);

    puts("+++ exited with 0 +++");
    return 0;
}
