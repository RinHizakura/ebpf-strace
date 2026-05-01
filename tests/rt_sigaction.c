#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>

static void handler(int sig)
{
    (void) sig;
}

int main()
{
    struct sigaction sa = {.sa_handler = handler};
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGUSR1, &sa, NULL) < 0)
        goto end;

    /* Read back the actual struct as installed (includes glibc-added
     * SA_RESTORER) */
    struct sigaction old;
    sigaction(SIGUSR1, NULL, &old);

    printf(
        "rt_sigaction(SIGUSR1, {sa_handler=0x%lx, sa_mask=[], "
        "sa_flags=SA_RESTORER, sa_restorer=0x%lx}, NULL, 8) = 0\n",
        (unsigned long) (uintptr_t) old.sa_handler,
        (unsigned long) (uintptr_t) old.sa_restorer);
end:
    puts("+++ exited with 0 +++");
    return 0;
}
