#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int map_invalid()
{
    void *addr = mmap(NULL, 0, PROT_NONE, MAP_FILE, 0, 0);
    if (addr != (void *) -1) {
        return -1;
    }
    printf(
        "mmap(NULL, 0, PROT_NONE, MAP_FILE, 0, 0x0) = -1 Invalid argument (os "
        "error %d)\n",
        errno);
    return 0;
}

static int map_valid()
{
    int ret = 0;

    int fd = open("bpf/strace.bpf.c", O_RDONLY);
    if (fd < 0)
        return -1;

    size_t pagesize = sysconf(_SC_PAGE_SIZE);
    off_t offset, pa_offset;
    offset = 4097;
    pa_offset = offset & ~(pagesize - 1);

    size_t length = pagesize * 6;
    size_t length2 = pagesize * 3;
    size_t length3 = pagesize * 2;

    void *addr = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, pa_offset);
    if (addr == NULL) {
        ret = -1;
        goto end;
    }
    printf("mmap(NULL, %ld, PROT_READ, MAP_PRIVATE, %d, 0x%lx) = 0x%lx\n",
           length, fd, pa_offset, (uintptr_t) addr);

    int result = mprotect(addr, length, PROT_READ | PROT_WRITE);
    if (result != 0) {
        ret = -1;
        goto end;
    }
    printf("mprotect(0x%lx, %ld, PROT_READ|PROT_WRITE) = %d\n",
           (uintptr_t) addr, length, result);

    void *p = mremap(addr, length, length2, 0);
    if (p == MAP_FAILED) {
        ret = -1;
        goto end;
    }
    printf("mremap(0x%lx, %ld, %ld, 0) = 0x%lx\n", (uintptr_t) addr, length,
           length2, (uintptr_t) p);

    void *p2 =
        mremap(p, length2, length3, MREMAP_MAYMOVE | MREMAP_FIXED, p + length2);
    if (p2 == MAP_FAILED) {
        ret = -1;
        goto end;
    }
    printf(
        "mremap(0x%lx, %ld, %ld, MREMAP_MAYMOVE|MREMAP_FIXED, 0x%lx) = 0x%lx\n",
        (uintptr_t) p, length2, length3, (uintptr_t) p + length2,
        (uintptr_t) p2);

    result = munmap(p2, length3);
    printf("munmap(0x%lx, %ld) = %d\n", (uintptr_t) p2, length3, result);

end:
    close(fd);
    return ret;
}

int main()
{
    int ret = 0;

    if (map_invalid() == -1) {
        ret = -1;
        goto end;
    }

    if (map_valid() == -1) {
        ret = -1;
        goto end;
    }

end:
    puts("+++ exited with 0 +++");
    return ret;
}
