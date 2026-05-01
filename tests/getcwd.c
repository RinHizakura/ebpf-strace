#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main()
{
    char buf[256];
    long ret = (long) getcwd(buf, sizeof(buf));
    if (ret < 0) {
        puts("+++ exited with 0 +++");
        return -1;
    }
    /* syscall returns string length including null terminator */
    printf("getcwd(\"%s\", %zu) = %zu\n", buf, sizeof(buf), strlen(buf) + 1);

    puts("+++ exited with 0 +++");
    return 0;
}
