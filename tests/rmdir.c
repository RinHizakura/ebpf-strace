#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *path = "/tmp/test_rmdir";
    if (mkdir(path, 0755) < 0) {
        ret = -1;
        goto end;
    }
    if (rmdir(path) < 0) {
        ret = -1;
        goto end;
    }
    printf("rmdir(\"%s\") = 0\n", path);
end:
    puts("+++ exited with 0 +++");
    return ret;
}
