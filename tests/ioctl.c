#include <fcntl.h>
#include <linux/random.h>
#include <sys/ioctl.h>
#include <unistd.h>

int do_ioctl_random()
{
    int ent_count;
    int random_fd = open("/dev/random", O_RDONLY);
    if (ioctl(random_fd, RNDGETENTCNT, &ent_count) != 0)
        return -1;
    close(random_fd);
    return 0;
}
