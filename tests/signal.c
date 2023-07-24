#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

static void handler(int sig,
                    siginfo_t *info,
                    __attribute__((unused)) void *ucontext)
{
    /* FIXME: The printf function is not Async-Signal-Safety,
     * considering other replacement. */
    if (sig == SIGUSR1 && info->si_code == SI_TKILL)
        printf(
            "--- SIGUSR1 {si_signo=SIGUSR1, si_code=SI_TKILL, si_pid=%d, "
            "si_uid=%d} ---\n",
            info->si_pid, info->si_uid);
}

#define RT_0 32
int main()
{
    sigset_t set, oldset;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, RT_0 + 3);
    int result = sigprocmask(SIG_SETMASK, &set, &oldset);
    if (result < 0)
        return -1;
    size_t sigsetsize = 8;  // FIXME: sizeof(kernel_sigset_t)
    printf("rt_sigprocmask(SIG_SETMASK, [USR2 CHLD RT_3], [], %ld) = %d\n",
           sigsetsize, result);

    struct sigaction sa = {.sa_sigaction = handler, .sa_flags = SA_SIGINFO};
    result = sigaction(SIGUSR1, &sa, NULL);
    if (result != 0)
        return -1;
    /* FIXME: How could we get sa_restorer for sigaction syscall? */

    if (raise(SIGUSR1))
        return -1;

    result = sigprocmask(SIG_SETMASK, &oldset, NULL);
    if (result < 0)
        return -1;
    printf("rt_sigprocmask(SIG_SETMASK, [], NULL, %ld) = %d\n", sigsetsize,
           result);

    puts("+++ exited with 0 +++");
    return 0;
}
