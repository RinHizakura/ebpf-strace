#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    int socks[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks) < 0) {
        ret = -1;
        goto end;
    }
    if (send(socks[0], "hello", 5, 0) != 5) {
        ret = -1;
        goto end;
    }
    char buf[6];
    ssize_t n = recv(socks[1], buf, 5, 0);
    if (n < 0 || n > 5) {
        ret = -1;
        goto end;
    }
    buf[n] = '\0';
    printf("recvfrom(%d, \"%s\", 5, 0, NULL, NULL) = %zd\n", socks[1], buf, n);
end:
    close(socks[0]);
    close(socks[1]);
    puts("+++ exited with 0 +++");
    return ret;
}
