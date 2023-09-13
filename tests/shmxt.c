#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>

static int id1 = -1;
static int id2 = -1;

static void __cleanup(int *id)
{
    if (*id != -1) {
        shmctl(*id, IPC_RMID, NULL);
        *id = -1;
    }
}

static void cleanup()
{
    __cleanup(&id1);
    __cleanup(&id2);
}

int main()
{
    atexit(cleanup);

    int ret = 0;
    id1 = shmget(IPC_PRIVATE, 1, 0600);
    if (id1 < 0) {
        ret = -1;
        goto end;
    }
    printf("shmget(IPC_PRIVATE, 1, 0600) = %d\n", id1);

    key_t key = 999;
    id2 = shmget(key, 1, 0666 | IPC_CREAT);
    if (id2 < 0) {
        ret = -1;
        goto end;
    }
    printf("shmget(0x%x, 1, IPC_CREAT|0666) = %d\n", key, id2);

    shmat(id1, NULL, SHM_REMAP);
    printf("shmat(%d, NULL, SHM_REMAP) = -1 %s (os error %d)\n", id1,
           strerror(errno), errno);

    void *shmaddr = shmat(id1, NULL, SHM_RDONLY);
    if (shmaddr == (void *) (-1)) {
        ret = -1;
        goto end;
    }
    printf("shmat(%d, NULL, SHM_RDONLY) = %p\n", id1, shmaddr);

end:
    puts("+++ exited with 0 +++");
    return ret;
}
