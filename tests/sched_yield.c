#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main()
{
    printf("sched_yield() = %ld\n", syscall(__NR_sched_yield));

    puts("+++ exited with 0 +++");
    return 0;
}
