#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#define ARR_ENT_SIZE 4

#define xsnprintf(pos, buf, sz, format, ...) \
    (pos) += snprintf((buf) + (pos), (sz) - (pos), format, ##__VA_ARGS__);

static char *format_mincore_vec(unsigned char *vec, size_t pages)
{
#define VEC_BUF_SIZE 512
    static char buf[VEC_BUF_SIZE];
    int pos = 0;

    xsnprintf(pos, buf, VEC_BUF_SIZE, "[");
    for (size_t i = 0; i < pages; i++) {
        if (i >= ARR_ENT_SIZE) {
            xsnprintf(pos, buf, VEC_BUF_SIZE, "...");
            break;
        }
        if (i)
            xsnprintf(pos, buf, VEC_BUF_SIZE, ",");
        xsnprintf(pos, buf, VEC_BUF_SIZE, "%u", vec[i] & 1);
    }
    xsnprintf(pos, buf, VEC_BUF_SIZE, "]");

    return buf;
}

static int test_mincore(size_t pages)
{
    const size_t pagesize = sysconf(_SC_PAGE_SIZE);
    const size_t size = pages * pagesize;

    void *addr =
        mmap(NULL, size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == NULL)
        return -1;

    unsigned char *vec = malloc(pages);

    int result = mincore(addr, size, vec);
    printf("mincore(%p, %zu, %s) = %d\n", addr, size,
           format_mincore_vec(vec, pages), result);

    munmap(addr, size);
    return 0;
}

int main()
{
    if (test_mincore(1))
        goto end;

    if (test_mincore(5))
        goto end;

end:
    puts("+++ exited with 0 +++");
    return 0;
}
