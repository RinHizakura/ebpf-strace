#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *path = "/tmp/test_chown";
    int fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        ret = -1;
        goto end;
    }
    close(fd);
    uid_t uid = getuid();
    gid_t gid = getgid();
    if (chown(path, uid, gid) < 0) {
        ret = -1;
        goto end;
    }
    printf("chown(\"%s\", %d, %d) = 0\n", path, (int) uid, (int) gid);
end:
    unlink(path);
    puts("+++ exited with 0 +++");
    return ret;
}
