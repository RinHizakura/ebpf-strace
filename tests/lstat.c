#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "xstatx.h"

int main()
{
    int ret = 0;

    const char *sample = "tests/sample.txt";
    struct stat sb;

    int rslt = syscall(SYS_lstat, sample, &sb);
    if (rslt == -1) {
        ret = -1;
        goto end;
    }
    char sb_str[512] = {0};
    format_stat(sb_str, 512, &sb);
    printf("lstat(\"%s\", %s) = %d\n", sample, sb_str, rslt);

end:
    puts("+++ exited with 0 +++");
    return ret;
}
