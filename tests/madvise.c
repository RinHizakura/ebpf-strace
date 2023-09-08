#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int main()
{
    const size_t size = sysconf(_SC_PAGE_SIZE);

    void *addr =
        mmap(NULL, size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == NULL)
        return -1;

    int result = madvise(addr, size, MADV_NORMAL);
    if (result == -1)
        goto end;
    printf("madvise(%p, %zu, MADV_NORMAL) = %d\n", addr, size, result);

    puts("+++ exited with 0 +++");
end:
    munmap(addr, size);
    return 0;
}
