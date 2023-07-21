#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main()
{
    const char *sample = "/test/sample.txt";
    int fd = open(sample, O_RDONLY);
    if (fd < 0)
        return -1;

    int ret = lseek(fd, 0, SEEK_SET);
    printf("lseek(%d, 0, SEEK_SET) = %d\n", fd, ret);
    close(fd);

    puts("+++ exited with 0 +++");
    return 0;
}

