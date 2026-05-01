#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *old = "/tmp/test_renameat_old";
    const char *new = "/tmp/test_renameat_new";
    int fd = open(old, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        ret = -1;
        goto end;
    }
    close(fd);
    if (renameat(AT_FDCWD, old, AT_FDCWD, new) < 0) {
        ret = -1;
        goto end;
    }
    printf("renameat(AT_FDCWD, \"%s\", AT_FDCWD, \"%s\") = 0\n", old, new);
end:
    unlink(old);
    unlink(new);
    puts("+++ exited with 0 +++");
    return ret;
}
