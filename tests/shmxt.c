#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>

int main()
{
    int ret = 0;
    int id = shmget(IPC_PRIVATE, 1, 0600);
    if (id < 0) {
        ret = -1;
        goto end;
    }
    printf("shmget(IPC_PRIVATE, 1, 0600) = %d\n", id);

    key_t key = 999;
    int id2 = shmget(key, 1, 0666 | IPC_CREAT);
    if (id2 < 0) {
        ret = -1;
        goto end;
    }
    printf("shmget(0x%x, 1, IPC_CREAT|0666) = %d\n", key, id2);

    shmat(id, NULL, SHM_REMAP);
    printf("shmat(%d, NULL, SHM_REMAP) = -1 %s (os error %d)\n", id,
           strerror(errno), errno);

    void *shmaddr = shmat(id, NULL, SHM_RDONLY);
    if (shmaddr == (void *) (-1)) {
        ret = -1;
        goto end;
    }
    printf("shmat(%d, NULL, SHM_RDONLY) = %p\n", id, shmaddr);

end:
    puts("+++ exited with 0 +++");
    return ret;
}
