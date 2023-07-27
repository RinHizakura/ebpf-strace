#include <fcntl.h>
#include <stdio.h>
#include <sys/uio.h>
#include <unistd.h>

static int format_iov(char *buf, size_t buf_sz, struct iovec *iov)
{
    int pos = 0;
    char *iov_base = iov->iov_base;

    pos += snprintf(buf, buf_sz, "{iov_base=\"");
    for (unsigned int i = 0; i < iov->iov_len; i++)
        pos += snprintf(buf + pos, buf_sz - pos, "%c", (char) iov_base[i]);
    pos += snprintf(buf + pos, buf_sz - pos, "\", iov_len=%ld}", iov->iov_len);

    return pos;
}

static int format_iovec(char *buf, size_t buf_sz, struct iovec *iov, int cnt)
{
    int pos = 0;

    pos += snprintf(buf, buf_sz, "[");
    for (int i = 0; i < cnt; i++) {
        if (i != 0)
            pos += snprintf(buf + pos, buf_sz - pos, ", ");
        pos += format_iov(buf + pos, buf_sz - pos, &iov[i]);
    }
    pos += snprintf(buf + pos, buf_sz - pos, "]");

    return pos;
}

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
    char iov_str[512] = {0};
    struct iovec iov = (struct iovec){
        .iov_base = buf,
        .iov_len = 32,
    };
    int iovcnt = 1;
    int r = readv(infd, &iov, iovcnt);
    format_iovec(iov_str, 512, &iov, iovcnt);
    printf("readv(%d, %s, %d) = %d\n", infd, iov_str, iovcnt, r);

    const char *tmpfile = "/tmp/tmpfile";
    outfd = open(tmpfile, O_CREAT | O_WRONLY);
    if (outfd < 0) {
        ret = -1;
        goto end;
    }
    int w = writev(outfd, &iov, iovcnt);
    format_iovec(iov_str, 512, &iov, iovcnt);
    printf("writev(%d, %s, %d) = %d\n", outfd, iov_str, iovcnt, w);

end:
    if (infd > 0)
        close(infd);
    if (outfd > 0)
        close(outfd);

    puts("+++ exited with 0 +++");
    return ret;
}
