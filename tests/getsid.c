#include <stdio.h>
#include <unistd.h>

int main()
{
    pid_t sid = getsid(0);
    if (sid < 0)
        goto end;
    printf("getsid(0) = %d\n", (int) sid);
end:
    puts("+++ exited with 0 +++");
    return 0;
}
