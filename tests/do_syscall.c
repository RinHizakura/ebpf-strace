#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
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

    lseek(fd, 0, SEEK_SET);

    close(fd);
    close(dirfd);

    return 0;
}

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

int do_poll()
{
    struct pollfd pfd;
    pfd.fd = STDIN_FILENO;
    pfd.events = POLLIN;

    poll(&pfd, 1, 0);

    return 0;
}

int do_map()
{
    int fd = open("bpf/strace.bpf.c", O_RDONLY);
    if (fd < 0)
        return -1;

    struct stat sb;
    if (fstat(fd, &sb) == -1)
        return -1;

    off_t offset, pa_offset;
    offset = 4097;
    pa_offset = offset & ~(sysconf(_SC_PAGE_SIZE) - 1);

    size_t length = (sb.st_size > pa_offset) ? sb.st_size - pa_offset : 0;
    void *addr = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, pa_offset);
    return (addr == NULL) ? -1 : 0;
}

int main()
{
    // TEST(do_file_operation);
    // TEST(do_stat);
    // TEST(do_poll);
    TEST(do_map);

    return 0;
}
