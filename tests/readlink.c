#include <stdio.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *target = "/tmp/test_readlink_target";
    const char *linkpath = "/tmp/test_readlink_link";
    if (symlink(target, linkpath) < 0) {
        ret = -1;
        goto end;
    }
    char buf[256];
    ssize_t n = readlink(linkpath, buf, sizeof(buf));
    if (n < 0) {
        ret = -1;
        goto end;
    }
    buf[n] = '\0';
    printf("readlink(\"%s\", \"%s\", %zu) = %zd\n", linkpath, buf, sizeof(buf),
           n);
end:
    unlink(linkpath);
    puts("+++ exited with 0 +++");
    return ret;
}
