#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "xstatx.h"

int main()
{
    int ret = 0;
    const char *sample = "tests/sample.txt";
    struct stat sb;

    int rslt = syscall(SYS_newfstatat, AT_FDCWD, sample, &sb, 0);
    if (rslt < 0) {
        ret = -1;
        goto end;
    }
    char sb_str[512] = {0};
    format_stat(sb_str, 512, &sb);
    printf("newfstatat(AT_FDCWD, \"%s\", %s, 0) = %d\n", sample, sb_str, rslt);

end:
    puts("+++ exited with 0 +++");
    return ret;
}
