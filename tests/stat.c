#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

int do_stat()
{
    struct stat sb;
    if (syscall(SYS_stat, "README.md", &sb) == -1)
        return -1;
    if (syscall(SYS_lstat, "README.md", &sb) == -1)
        return -1;
    if (stat("README.md", &sb) == -1)
        return -1;

    int fd = open("README.md", O_RDONLY);
    if (fd < 0)
        return -1;
    if (syscall(SYS_fstat, fd, &sb) == -1)
        return -1;
    close(fd);

    return 0;
}
