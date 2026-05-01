#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

struct linux_dirent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

static const char *dtype_str(unsigned char d_type)
{
    switch (d_type) {
    case 0:
        return "DT_UNKNOWN";
    case 1:
        return "DT_FIFO";
    case 2:
        return "DT_CHR";
    case 4:
        return "DT_DIR";
    case 6:
        return "DT_BLK";
    case 8:
        return "DT_REG";
    case 10:
        return "DT_LNK";
    case 12:
        return "DT_SOCK";
    case 14:
        return "DT_WHT";
    default:
        return "DT_UNKNOWN";
    }
}

int main()
{
    int ret = 0;
    int fd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        ret = -1;
        goto end;
    }
    char buf[4096];
    size_t count = sizeof(buf);
    long n = syscall(SYS_getdents64, fd, buf, count);
    if (n < 0) {
        ret = -1;
        goto end;
    }

    printf("getdents64(%d, [", fd);
    long offset = 0;
    int first = 1;
    while (offset < n) {
        struct linux_dirent64 *d = (struct linux_dirent64 *) (buf + offset);
        if (!first)
            printf(", ");
        printf(
            "{d_ino=%llu, d_off=%lld, d_reclen=%hu, d_type=%s, d_name=\"%s\"}",
            d->d_ino, d->d_off, d->d_reclen, dtype_str(d->d_type), d->d_name);
        first = 0;
        offset += d->d_reclen;
    }
    printf("], %zu) = %ld\n", count, n);

end:
    if (fd >= 0)
        close(fd);
    puts("+++ exited with 0 +++");
    return ret;
}
