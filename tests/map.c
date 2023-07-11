#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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
