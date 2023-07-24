#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main()
{
    long result = syscall(__NR_brk, NULL);
    printf("brk(NULL) = 0x%lx\n", result);

    puts("+++ exited with 0 +++");
    return 0;
}
