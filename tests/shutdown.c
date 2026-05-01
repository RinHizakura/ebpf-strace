#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main()
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        goto end;
    if (shutdown(fd, SHUT_RDWR) < 0) {
        close(fd);
        goto end;
    }
    printf("shutdown(%d, SHUT_RDWR) = 0\n", fd);
    close(fd);
end:
    puts("+++ exited with 0 +++");
    return 0;
}
