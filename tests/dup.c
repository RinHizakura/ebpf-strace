#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int main()
{
    int ret = 0;

    int fd0 = dup(0);
    if (fd0 < 0) {
        ret = -1;
        goto end;
    }
    printf("dup(0) = %d\n", fd0);
    close(fd0);

    int fd9 = dup(9);
    if (fd9 < 0) {
        printf("dup(9) = %d %s (os error %d)\n", fd9, strerror(errno), errno);
    } else {
        printf("dup(9) = %d\n", fd9);
        close(fd9);
    }

    int fd = open("tests/sample.txt", O_RDONLY);
    if (fd0 < 0) {
        ret = -1;
        goto end;
    }
    int fd_dup = dup2(fd, 0);
    if (fd_dup != 0) {
        ret = -1;
        goto end;
    }
    printf("dup2(%d, 0) = 0\n", fd);

end:
    puts("+++ exited with 0 +++");
    return ret;
}
