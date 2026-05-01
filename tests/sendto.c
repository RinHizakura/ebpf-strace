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
    ssize_t n = send(socks[0], "hello", 5, 0);
    if (n < 0) {
        ret = -1;
        goto end;
    }
    printf("sendto(%d, \"hello\", 5, 0, NULL, 0) = %zd\n", socks[0], n);
end:
    close(socks[0]);
    close(socks[1]);
    puts("+++ exited with 0 +++");
    return ret;
}
