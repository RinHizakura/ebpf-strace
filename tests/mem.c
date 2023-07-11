#include <stdlib.h>

int do_mem()
{
    void *ptr = malloc(4096);
    free(ptr);
    return 0;
}
