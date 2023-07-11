#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

int do_file()
{
    int dirfd = syscall(SYS_open, "../ebpf-strace", O_DIRECTORY | O_RDONLY);
    if (dirfd < 0)
        return -1;

    int fd = openat(dirfd, "README.md", O_RDONLY);
    if (fd < 0)
        return -1;

    int new_fd = open("/tmp/test", O_CREAT | O_WRONLY, 0666);
    if (new_fd < 0)
        return -1;

    lseek(fd, 0, SEEK_SET);

    uint8_t buf[32];
    pread(fd, buf, 32, 32);
    memset(buf, 'A', sizeof(buf));
    pwrite(new_fd, buf, 32, 32);

    struct iovec iov = (struct iovec){
        .iov_base = buf,
        .iov_len = 32,
    };
    readv(fd, &iov, 1);
    memset(buf, 'A', sizeof(buf));
    writev(new_fd, &iov, 1);

    close(new_fd);
    close(fd);
    close(dirfd);

    return 0;
}
