#include <stdio.h>
#include <unistd.h>

int main()
{
    if (chdir("/tmp") < 0)
        goto end;
    printf("chdir(\"/tmp\") = 0\n");
end:
    puts("+++ exited with 0 +++");
    return 0;
}
