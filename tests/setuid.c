#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main()
{
    uid_t uid = getuid();
    if (setuid(uid) < 0)
        goto end;
    printf("setuid(%d) = 0\n", (int) uid);
end:
    puts("+++ exited with 0 +++");
    return 0;
}
