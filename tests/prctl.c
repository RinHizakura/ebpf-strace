#include <stdio.h>
#include <sys/prctl.h>

static const char *dumpable_name(int val)
{
    switch (val) {
    case 0:
        return " (SUID_DUMP_DISABLE)";
    case 1:
        return " (SUID_DUMP_USER)";
    case 2:
        return " (SUID_DUMP_ROOT)";
    default:
        return "";
    }
}

int main()
{
    /* PR_GET_DUMPABLE = 3 */
    int ret = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    printf("prctl(PR_GET_DUMPABLE) = %d%s\n", ret, dumpable_name(ret));

    puts("+++ exited with 0 +++");
    return 0;
}
