#include <fcntl.h>
#include <linux/random.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main()
{
    int ret = 0;
    int ent_count;
    int random_fd = open("/dev/random", O_RDONLY);
    int result = ioctl(random_fd, RNDGETENTCNT, &ent_count);
    if (result != 0) {
        goto end;
        ret = -1;
    }
    printf("ioctl(%d, RNDGETENTCNT, %d) = %d\n", random_fd, ent_count, result);

end:
    close(random_fd);
    puts("+++ exited with 0 +++");
    return ret;
}
