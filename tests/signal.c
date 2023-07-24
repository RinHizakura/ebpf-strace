#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static bool getsig = false;
static struct {
    int sig;
    siginfo_t info;
} sig_message;

static void handler(int sig,
                    siginfo_t *info,
                    __attribute__((unused)) void *ucontext)
{
    if (getsig == false) {
        sig_message.sig = sig;
        memcpy(&(sig_message.info), info, sizeof(siginfo_t));
    }

    getsig = true;
}

static char *signame(int sig)
{
    switch (sig) {
    case SIGUSR1:
        return "SIGUSR1";
    default:
        return "Unknown";
    }
}

static void format_signal(int sig, siginfo_t *info)
{
    printf("--- %s {si_signo=%s", signame(sig), signame(info->si_signo));

    switch (info->si_code) {
    case SI_TKILL:
        printf(", si_code=SI_TKILL, si_pid=%d, si_uid=%d", info->si_pid,
               info->si_uid);
        break;
    default:
        break;
    }

    printf("} ---\n");
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
    while (!getsig)
        ;  // busy waiting until we get the first signal
    format_signal(sig_message.sig, &sig_message.info);

    result = sigprocmask(SIG_SETMASK, &oldset, NULL);
    if (result < 0)
        return -1;
    printf("rt_sigprocmask(SIG_SETMASK, [], NULL, %ld) = %d\n", sigsetsize,
           result);

    puts("+++ exited with 0 +++");
    return 0;
}
