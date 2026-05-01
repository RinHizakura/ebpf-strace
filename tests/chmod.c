#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *path = "/tmp/test_chmod";
    int fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        ret = -1;
        goto end;
    }
    close(fd);
    if (chmod(path, 0644) < 0) {
        ret = -1;
        goto end;
    }
    printf("chmod(\"%s\", 0644) = 0\n", path);
end:
    unlink(path);
    puts("+++ exited with 0 +++");
    return ret;
}
