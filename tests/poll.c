#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void format_revents(short revents, char *buf, size_t sz)
{
    buf[0] = '\0';
    const struct {
        short val;
        const char *name;
    } flags[] = {
        {POLLIN, "POLLIN"},   {POLLPRI, "POLLPRI"}, {POLLOUT, "POLLOUT"},
        {POLLHUP, "POLLHUP"}, {POLLERR, "POLLERR"}, {POLLNVAL, "POLLNVAL"},
    };
    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        if (revents & flags[i].val) {
            if (buf[0])
                strncat(buf, "|", sz - strlen(buf) - 1);
            strncat(buf, flags[i].name, sz - strlen(buf) - 1);
        }
    }
}

int main()
{
    struct pollfd pfd;
    pfd.fd = STDIN_FILENO;
    pfd.events = POLLIN;

    int ret = poll(&pfd, 1, 0);
    if (ret > 0) {
        char revents_str[64];
        format_revents(pfd.revents, revents_str, sizeof(revents_str));
        printf(
            "poll([{fd=%d, events=POLLIN}], 1, 0) = %d ([{fd=%d, "
            "revents=%s}])\n",
            STDIN_FILENO, ret, STDIN_FILENO, revents_str);
    } else if (ret == 0) {
        printf("poll([{fd=%d, events=POLLIN}], 1, 0) = 0 (Timeout)\n",
               STDIN_FILENO);
    } else {
        printf("poll([{fd=%d, events=POLLIN}], 1, 0) = %d\n", STDIN_FILENO,
               ret);
    }

    puts("+++ exited with 0 +++");
    return 0;
}
