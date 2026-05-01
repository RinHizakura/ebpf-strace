#include <stdio.h>
#include <sys/prctl.h>

int main()
{
    /* PR_GET_DUMPABLE = 3 */
    int ret = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    printf("prctl(%d, 0x0) = %d\n", PR_GET_DUMPABLE, ret);

    puts("+++ exited with 0 +++");
    return 0;
}
