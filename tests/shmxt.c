#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>

int main()
{
    int id = shmget(IPC_PRIVATE, 1, 0600);
    if (id < 0)
        goto end;
    printf("shmget(IPC_PRIVATE, 1, 0600) = %d\n", id);

    key_t key = 999;
    int id2 = shmget(key, 1, 0666 | IPC_CREAT);
    if (id2 < 0)
        goto end;
    printf("shmget(0x%x, 1, IPC_CREAT|0666) = %d\n", key, id2);

end:
    puts("+++ exited with 0 +++");
    return 0;
}
