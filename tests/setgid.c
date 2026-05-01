#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main()
{
    gid_t gid = getgid();
    if (setgid(gid) < 0)
        goto end;
    printf("setgid(%d) = 0\n", (int) gid);
end:
    puts("+++ exited with 0 +++");
    return 0;
}
