#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *old = "/tmp/test_rename_old";
    const char *new = "/tmp/test_rename_new";
    int fd = open(old, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        ret = -1;
        goto end;
    }
    close(fd);
    if (rename(old, new) < 0) {
        ret = -1;
        goto end;
    }
    printf("rename(\"%s\", \"%s\") = 0\n", old, new);
end:
    unlink(old);
    unlink(new);
    puts("+++ exited with 0 +++");
    return ret;
}
