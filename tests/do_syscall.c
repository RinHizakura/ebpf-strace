#include <fcntl.h>
#include <linux/random.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ioctl.h>
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
    if (addr == NULL)
        return -1;

    if (mprotect(addr, length, PROT_WRITE) != 0)
        return -1;
    munmap(addr, length);
    return 0;
}

int do_mem()
{
    void *ptr = malloc(4096);
    free(ptr);
    return 0;
}

static void handler(int no, siginfo_t *si, void *uc)
{
    /* dummy */
}

#define RT_0 32
int do_signal()
{
    sigset_t set, oldset;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, RT_0 + 3);
    if (sigprocmask(SIG_SETMASK, &set, &oldset))
        return -1;

    struct sigaction sa = {.sa_sigaction = handler, .sa_flags = SA_SIGINFO};
    if (sigaction(SIGUSR1, &sa, NULL))
        return -1;

    if (raise(SIGUSR1))
        return -1;

    if (sigprocmask(SIG_SETMASK, &oldset, NULL) < 0)
        return -1;

    return 0;
}

int do_ioctl_random()
{
    int ent_count;
    int random_fd = open("/dev/random", O_RDONLY);
    if (ioctl(random_fd, RNDGETENTCNT, &ent_count) != 0)
        return -1;
    close(random_fd);
    return 0;
}

int main()
{
    // TEST(do_file_operation);
    // TEST(do_stat);
    // TEST(do_poll);
    // TEST(do_map);
    // TEST(do_mem);
    // TEST(do_signal);
    TEST(do_ioctl_random);

    return 0;
}
