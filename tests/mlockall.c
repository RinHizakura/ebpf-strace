#include <stdio.h>
#include <sys/mman.h>

int main()
{
    if (mlockall(MCL_CURRENT) < 0)
        goto end;
    printf("mlockall(MCL_CURRENT) = 0\n");
    munlockall();
end:
    puts("+++ exited with 0 +++");
    return 0;
}
