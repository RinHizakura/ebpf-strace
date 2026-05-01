#include <signal.h>
#include <stdio.h>

int main()
{
    sigset_t set, old;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);

    if (sigprocmask(SIG_BLOCK, &set, &old) < 0)
        goto end;
    printf("rt_sigprocmask(SIG_BLOCK, [USR1], [], 8) = 0\n");

    if (sigprocmask(SIG_UNBLOCK, &set, &old) < 0)
        goto end;
    printf("rt_sigprocmask(SIG_UNBLOCK, [USR1], [USR1], 8) = 0\n");
end:
    puts("+++ exited with 0 +++");
    return 0;
}
