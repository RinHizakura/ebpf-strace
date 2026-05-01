#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    size_t pagesize = sysconf(_SC_PAGE_SIZE);
    void *addr = mmap(NULL, pagesize, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        ret = -1;
        goto end;
    }
    if (msync(addr, pagesize, MS_SYNC) < 0) {
        ret = -1;
        goto end;
    }
    printf("msync(%p, %zu, MS_SYNC) = 0\n", addr, pagesize);
    munmap(addr, pagesize);
end:
    puts("+++ exited with 0 +++");
    return ret;
}
