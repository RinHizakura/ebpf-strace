#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *path = "/tmp/test_fchown";
    int fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        ret = -1;
        goto end;
    }
    uid_t uid = getuid();
    gid_t gid = getgid();
    if (fchown(fd, uid, gid) < 0) {
        ret = -1;
        goto end;
    }
    printf("fchown(%d, %d, %d) = 0\n", fd, (int) uid, (int) gid);
end:
    if (fd >= 0)
        close(fd);
    unlink(path);
    puts("+++ exited with 0 +++");
    return ret;
}
