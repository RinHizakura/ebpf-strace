#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *orig = "/tmp/test_link_orig";
    const char *dest = "/tmp/test_link_dest";
    int fd = open(orig, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        ret = -1;
        goto end;
    }
    close(fd);
    if (link(orig, dest) < 0) {
        ret = -1;
        goto end;
    }
    printf("link(\"%s\", \"%s\") = 0\n", orig, dest);
end:
    unlink(orig);
    unlink(dest);
    puts("+++ exited with 0 +++");
    return ret;
}
