#include "do_syscall.h"

#define TEST(f) \
    if (f())    \
    return -1

int main()
{
    TEST(do_file);
    // TEST(do_stat);
    // TEST(do_poll);
    // TEST(do_map);
    // TEST(do_mem);
    // TEST(do_signal);
    // TEST(do_ioctl_random);

    return 0;
}
