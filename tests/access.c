#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *sample = "tests/sample.txt";
    int fd = open(sample, O_RDONLY);
    if (fd < 0) {
        ret = -1;
        goto end;
    }

    int rslt = access(sample, R_OK | W_OK);
    if (rslt < 0) {
        ret = -1;
        goto end;
    }
    printf("access(\"%s\", R_OK|W_OK) = %d\n", sample, rslt);

end:
    if (fd > 0)
        close(fd);

    puts("+++ exited with 0 +++");
    return ret;
}
