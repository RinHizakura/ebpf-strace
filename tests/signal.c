#include <signal.h>
#include <stddef.h>

static void handler(int no, siginfo_t *si, void *uc)
{
    /* dummy */
}

#define RT_0 32
int do_signal()
{
    sigset_t set, oldset;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, RT_0 + 3);
    if (sigprocmask(SIG_SETMASK, &set, &oldset))
        return -1;

    struct sigaction sa = {.sa_sigaction = handler, .sa_flags = SA_SIGINFO};
    if (sigaction(SIGUSR1, &sa, NULL))
        return -1;

    if (raise(SIGUSR1))
        return -1;

    if (sigprocmask(SIG_SETMASK, &oldset, NULL) < 0)
        return -1;

    return 0;
}
