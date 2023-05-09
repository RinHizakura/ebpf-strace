#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define TEST(f) \
    if (f())    \
    return -1

int do_file_operation()
{
    int dirfd = syscall(SYS_open, "../ebpf-strace", O_DIRECTORY | O_RDONLY);
    if (dirfd < 0)
        return -1;

    int fd = openat(dirfd, "README.md", O_RDONLY);
    if (fd < 0)
        return -1;

    close(fd);
    close(dirfd);

    return 0;
}

int do_stat()
{
    struct stat sb;
    if (syscall(SYS_stat, "README.md", &sb) == -1)
        return -1;
    return 0;
}

int main()
{
    // TEST(do_file_operation);
    TEST(do_stat);

    return 0;
}
