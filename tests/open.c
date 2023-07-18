#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main()
{
    const char *dir = "tests";
    int dirfd = syscall(SYS_open, dir, O_DIRECTORY);
    if (dirfd < 0)
        return -1;
    printf("open(\"%s\", O_DIRECTORY) = %d\n", dir, dirfd);

    puts("+++ exited with 0 +++");
    return 0;
}
