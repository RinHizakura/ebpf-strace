#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *path = "/tmp/test_bind.sock";
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) {
        ret = -1;
        goto end;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    socklen_t addrlen =
        offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1;
    if (bind(sfd, (struct sockaddr *) &addr, addrlen) < 0) {
        ret = -1;
        goto end;
    }
    printf("bind(%d, {sa_family=AF_UNIX, sun_path=\"%s\"}, %u) = 0\n", sfd,
           path, (unsigned) addrlen);
end:
    if (sfd >= 0)
        close(sfd);
    unlink(path);
    puts("+++ exited with 0 +++");
    return ret;
}
