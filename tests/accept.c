#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    const char *path = "/tmp/test_accept.sock";
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
    if (listen(sfd, 1) < 0) {
        ret = -1;
        goto end;
    }

    pid_t child = fork();
    if (child < 0) {
        ret = -1;
        goto end;
    }
    if (child == 0) {
        int cfd = socket(AF_UNIX, SOCK_STREAM, 0);
        connect(cfd, (struct sockaddr *) &addr, addrlen);
        _exit(0);
    }

    struct sockaddr_un peer;
    socklen_t peerlen = sizeof(peer);
    socklen_t peerlen_init = peerlen;
    int afd = accept(sfd, (struct sockaddr *) &peer, &peerlen);
    if (afd < 0) {
        ret = -1;
        goto child_wait;
    }
    printf("accept(%d, {sa_family=AF_UNIX}, [%u => %u]) = %d\n", sfd,
           (unsigned) peerlen_init, (unsigned) peerlen, afd);
    close(afd);

child_wait:
    waitpid(child, NULL, 0);
end:
    if (sfd >= 0)
        close(sfd);
    unlink(path);
    puts("+++ exited with 0 +++");
    return ret;
}
