#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *path = "/tmp/test_mkdir";
    if (mkdir(path, 0755) < 0) {
        ret = -1;
        goto end;
    }
    printf("mkdir(\"%s\", 0755) = 0\n", path);
end:
    rmdir(path);
    puts("+++ exited with 0 +++");
    return ret;
}
