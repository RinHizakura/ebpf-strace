#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    int infd = -1;
    int outfd1 = -1;
    int outfd2 = -1;

    const char *sample = "tests/sample.txt";
    infd = open(sample, O_RDONLY);
    if (infd < 0) {
        ret = -1;
        goto end;
    }
    char buf[32] = {0};
    int cnt = 16;
    int r = read(infd, buf, cnt);
    printf("read(%d, \"%s\", %d) = %d\n", infd, buf, cnt, r);

    const char *tmpfile = "/tmp/tmpfile";
    outfd1 = open(tmpfile, O_CREAT | O_WRONLY);
    if (outfd1 < 0) {
        ret = -1;
        goto end;
    }
    int w = write(outfd1, buf, cnt);
    printf("write(%d, \"%s\", %d) = %d\n", outfd1, buf, cnt, w);

    tmpfile = "/tmp/tmpfile";
    outfd2 = open(tmpfile, O_RDONLY);
    if (outfd2 < 0) {
        ret = -1;
        goto end;
    }
    w = write(outfd2, buf, cnt);
    printf("write(%d, \"%s\", %d) = %d %s (os error %d)\n", outfd2, buf, cnt, w,
           strerror(errno), errno);

end:
    if (infd > 0)
        close(infd);
    if (outfd1 > 0)
        close(outfd1);
    if (outfd2 > 0)
        close(outfd2);

    puts("+++ exited with 0 +++");
    return ret;
}
