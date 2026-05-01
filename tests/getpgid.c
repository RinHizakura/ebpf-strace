#include <stdio.h>
#include <unistd.h>

int main()
{
    pid_t pgid = getpgid(0);
    if (pgid < 0)
        goto end;
    printf("getpgid(0) = %d\n", (int) pgid);
end:
    puts("+++ exited with 0 +++");
    return 0;
}
