#include <signal.h>
#include <stdbool.h>
#include <stdio.h>

static bool handled = false;

static void handler(int sig)
{
    (void) sig;
    handled = true;
    /* rt_sigreturn is called implicitly when this returns */
}

int main()
{
    struct sigaction sa = {.sa_handler = handler};
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);

    raise(SIGUSR1);
    while (!handled)
        ;

    /* rt_sigreturn captures the signal mask from the signal frame.
     * With no blocked signals set, the mask is empty. */
    printf("rt_sigreturn([]) = ?\n");

    puts("+++ exited with 0 +++");
    return 0;
}
