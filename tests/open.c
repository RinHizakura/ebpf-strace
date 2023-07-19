#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    int fd1 = -1;
    int fd2 = -1;
    int fd3 = -1;

    const char *tmpfile = "/tmp/tmpfile";
    int mode = 0400;
    fd1 = syscall(SYS_open, tmpfile, O_CREAT, mode);
    if (fd1 < 0) {
        ret = -1;
        goto end;
    }
    printf("open(\"%s\", O_CREAT, 0%o) = %d\n", tmpfile, mode, fd1);

    fd2 = syscall(SYS_open, tmpfile, O_RDONLY);
    if (fd2 < 0) {
        ret = -1;
        goto end;
    }
    printf("open(\"%s\", O_RDONLY) = %d\n", tmpfile, fd2);

    fd3 = syscall(SYS_open, tmpfile, O_WRONLY | O_NONBLOCK | 0x80000000);
    if (fd3 < 0) {
        ret = -1;
        goto end;
    }
    printf("open(\"%s\", O_WRONLY|O_NONBLOCK|0x80000000) = %d\n", tmpfile, fd3);

end:
    if (fd1 > 0)
        close(fd1);
    if (fd2 > 0)
        close(fd2);
    if (fd3 > 0)
        close(fd3);
    puts("+++ exited with 0 +++");
    return 0;
}
