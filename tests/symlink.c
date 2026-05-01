#include <stdio.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *target = "/tmp/test_symlink_target";
    const char *linkpath = "/tmp/test_symlink_link";
    if (symlink(target, linkpath) < 0) {
        ret = -1;
        goto end;
    }
    printf("symlink(\"%s\", \"%s\") = 0\n", target, linkpath);
end:
    unlink(linkpath);
    puts("+++ exited with 0 +++");
    return ret;
}
