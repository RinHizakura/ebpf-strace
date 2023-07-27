#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    int infd = -1;
    int outfd = -1;

    const char *sample = "tests/sample.txt";
    infd = open(sample, O_RDONLY);
    if (infd < 0) {
        ret = -1;
        goto end;
    }

    char buf[32] = {0};
    int cnt = 16;
    int offset = 16;
    int r = pread(infd, buf, cnt, offset);
    printf("pread64(%d, \"%s\", %d, %d) = %d\n", infd, buf, cnt, offset, r);

    const char *tmpfile = "/tmp/tmpfile";
    outfd = open(tmpfile, O_CREAT | O_WRONLY);
    if (outfd < 0) {
        ret = -1;
        goto end;
    }
    int w = pwrite(outfd, buf, cnt, offset);
    printf("pwrite64(%d, \"%s\", %d, %d) = %d\n", outfd, buf, cnt, offset, w);


end:
    if (infd > 0)
        close(infd);
    if (outfd > 0)
        close(outfd);

    puts("+++ exited with 0 +++");
    return ret;
}
