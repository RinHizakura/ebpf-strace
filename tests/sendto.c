#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

int main()
{
    int ret = 0;

    /* NULL addr case (send maps to sendto with NULL, 0) */
    int socks[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks) < 0) {
        ret = -1;
        goto end;
    }
    ssize_t n = syscall(SYS_sendto, socks[0], "hello", 5, 0, NULL, 0);
    if (n < 0) {
        ret = -1;
        goto end;
    }
    printf("sendto(%d, \"hello\", 5, 0, NULL, 0) = %zd\n", socks[0], n);
    close(socks[0]);
    close(socks[1]);

    /* AF_INET addr case */
    int srv = socket(AF_INET, SOCK_DGRAM, 0);
    if (srv < 0) {
        ret = -1;
        goto end;
    }
    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = 0;
    saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(srv, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
        ret = -1;
        goto end;
    }
    struct sockaddr_in bound;
    socklen_t blen = sizeof(bound);
    if (getsockname(srv, (struct sockaddr *) &bound, &blen) < 0) {
        ret = -1;
        goto end;
    }

    int cli = socket(AF_INET, SOCK_DGRAM, 0);
    if (cli < 0) {
        ret = -1;
        goto end;
    }
    n = sendto(cli, "hi", 2, 0, (struct sockaddr *) &bound, sizeof(bound));
    if (n < 0) {
        ret = -1;
        goto end;
    }
    printf(
        "sendto(%d, \"hi\", 2, 0, {sa_family=AF_INET, sin_port=htons(%u), "
        "sin_addr=inet_addr(\"127.0.0.1\")}, %u) = %zd\n",
        cli, ntohs(bound.sin_port), (unsigned) sizeof(bound), n);
    close(srv);
    close(cli);

end:
    puts("+++ exited with 0 +++");
    return ret;
}
