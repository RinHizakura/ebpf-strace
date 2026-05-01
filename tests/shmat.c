#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>

int main()
{
    int ret = 0;
    int id = shmget(IPC_PRIVATE, 4096, 0600);
    if (id < 0) {
        ret = -1;
        goto end;
    }
    void *addr = shmat(id, NULL, 0);
    if (addr == (void *) -1) {
        ret = -1;
        goto end;
    }
    printf("shmat(%d, NULL, 0) = %p\n", id, addr);
    shmdt(addr);
    shmctl(id, IPC_RMID, NULL);
end:
    puts("+++ exited with 0 +++");
    return ret;
}
