#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include "xstatx.h"

int main()
{
    int ret = 0;

    const char *sample = "tests/sample.txt";
    struct stat sb;

    int fd = open(sample, O_RDONLY);
    if (fd < 0) {
        ret = -1;
        goto end;
    }
    int rslt = syscall(SYS_fstat, fd, &sb);
    if (rslt == -1) {
        close(fd);
        ret = -1;
        goto end;
    }
    char sb_str[512] = {0};
    format_stat(sb_str, 512, &sb);
    printf("fstat(%d, %s) = %d\n", fd, sb_str, rslt);

    close(fd);
end:
    puts("+++ exited with 0 +++");
    return ret;
}
