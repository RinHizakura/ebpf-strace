#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *path = "/tmp/test_mkdirat";
    if (mkdirat(AT_FDCWD, path, 0755) < 0) {
        ret = -1;
        goto end;
    }
    printf("mkdirat(AT_FDCWD, \"%s\", 0755) = 0\n", path);
end:
    rmdir(path);
    puts("+++ exited with 0 +++");
    return ret;
}
