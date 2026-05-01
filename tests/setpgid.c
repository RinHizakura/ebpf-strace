#include <stdio.h>
#include <unistd.h>

int main()
{
    if (setpgid(0, 0) < 0)
        goto end;
    printf("setpgid(0, 0) = 0\n");
end:
    puts("+++ exited with 0 +++");
    return 0;
}
