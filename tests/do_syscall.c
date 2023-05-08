#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define TEST(f)       \
    if(f())           \
        return -1     \

int do_file_operation()
{
    long fd = syscall(SYS_open, "README.md", O_RDONLY);
    if (fd < 0)
        return -1;
    syscall(SYS_close, fd);

    return 0;
}

int do_file_operation_2()
{
    int dirfd = open("../ebpf-strace", O_DIRECTORY | O_RDONLY);
    if (dirfd < 0)
        return -1;

    int fd = openat(dirfd, "README.md", O_RDONLY);
    if (fd < 0)
        return -1;

    close(fd);
    close(dirfd);

    return 0;
}

int main()
{
    //TEST(do_file_operation);
    TEST(do_file_operation_2);

    return 0;
}
