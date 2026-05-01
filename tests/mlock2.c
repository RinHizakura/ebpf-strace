#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
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
    long r = syscall(SYS_mlock2, addr, pagesize, 0);
    if (r < 0) {
        ret = -1;
        goto end;
    }
    printf("mlock2(%p, %zu, 0) = 0\n", addr, pagesize);
    munlock(addr, pagesize);
    munmap(addr, pagesize);
end:
    puts("+++ exited with 0 +++");
    return ret;
}
