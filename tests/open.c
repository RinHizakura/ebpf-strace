#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    char tmpfile[64];
    snprintf(tmpfile, sizeof(tmpfile), "/tmp/test_open_%d", getpid());
    int mode = 0600;
    int fd1 = -1, fd2 = -1, fd3 = -1;

    fd1 = syscall(SYS_open, tmpfile, O_CREAT | O_WRONLY, mode);
    if (fd1 < 0) {
        ret = -1;
        goto end;
    }
    printf("open(\"%s\", O_WRONLY|O_CREAT, 0%o) = %d\n", tmpfile, mode, fd1);

    fd2 = syscall(SYS_open, tmpfile, O_RDONLY);
    if (fd2 < 0) {
        ret = -1;
        goto end;
    }
    printf("open(\"%s\", O_RDONLY) = %d\n", tmpfile, fd2);

    fd3 = syscall(SYS_open, tmpfile, O_WRONLY | O_NONBLOCK);
    if (fd3 < 0) {
        ret = -1;
        goto end;
    }
    printf("open(\"%s\", O_WRONLY|O_NONBLOCK) = %d\n", tmpfile, fd3);

end:
    if (fd1 >= 0)
        close(fd1);
    if (fd2 >= 0)
        close(fd2);
    if (fd3 >= 0)
        close(fd3);
    unlink(tmpfile);
    puts("+++ exited with 0 +++");
    return ret;
}
