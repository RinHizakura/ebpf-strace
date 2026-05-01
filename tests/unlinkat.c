#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *path = "/tmp/test_unlinkat";
    int fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        ret = -1;
        goto end;
    }
    close(fd);
    if (unlinkat(AT_FDCWD, path, 0) < 0) {
        ret = -1;
        goto end;
    }
    printf("unlinkat(AT_FDCWD, \"%s\", 0) = 0\n", path);
end:
    puts("+++ exited with 0 +++");
    return ret;
}
