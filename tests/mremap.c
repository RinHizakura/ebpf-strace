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
    void *new_addr = mremap(addr, pagesize, pagesize * 2, MREMAP_MAYMOVE);
    if (new_addr == MAP_FAILED) {
        ret = -1;
        goto end;
    }
    printf("mremap(%p, %zu, %zu, MREMAP_MAYMOVE) = %p\n", addr, pagesize,
           pagesize * 2, new_addr);
    munmap(new_addr, pagesize * 2);
end:
    puts("+++ exited with 0 +++");
    return ret;
}
