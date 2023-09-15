#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>

static int id = -1;

static void cleanup(void)
{
    shmctl(id, IPC_RMID, NULL);
    printf("shmctl(%d, IPC_RMID, NULL) = 0\n", id);
    id = -1;
}

static void print_shmid_ds(char *str_ipc_cmd, struct shmid_ds *ds, int rc)
{
    printf(
        "shmctl(%d, %s, {shm_perm={uid=%u, gid=%u"
        ", mode=%#o, key=%u, cuid=%u, cgid=%u}, shm_segsz=%u"
        ", shm_cpid=%d, shm_lpid=%d, shm_nattch=%u, shm_atime=%u"
        ", shm_dtime=%u, shm_ctime=%u}) = %d\n",
        id, str_ipc_cmd, (unsigned) ds->shm_perm.uid,
        (unsigned) ds->shm_perm.gid, (unsigned) ds->shm_perm.mode,
        (unsigned) ds->shm_perm.__key, (unsigned) ds->shm_perm.cuid,
        (unsigned) ds->shm_perm.cgid, (unsigned) ds->shm_segsz,
        (int) ds->shm_cpid, (int) ds->shm_lpid, (unsigned) ds->shm_nattch,
        (unsigned) ds->shm_atime, (unsigned) ds->shm_dtime,
        (unsigned) ds->shm_ctime, rc);
}

int main()
{
    int ret = 0;
    struct shmid_ds ds;

    id = shmget(IPC_PRIVATE, 1, 0600);
    printf("shmget(IPC_PRIVATE, 1, 0600) = %d\n", id);
    atexit(cleanup);

    int rc = shmctl(id, IPC_STAT, &ds);
    if (rc < 0) {
        ret = -1;
        goto end;
    }
    print_shmid_ds("IPC_STAT", &ds, rc);

    rc = shmctl(id, IPC_SET, &ds);
    printf("shmctl(%d, IPC_SET, {shm_perm={uid=%u, gid=%u, mode=%#o}}) = 0\n",
           id, (unsigned) ds.shm_perm.uid, (unsigned) ds.shm_perm.gid,
           (unsigned) ds.shm_perm.mode);

    rc = shmctl(id, SHM_STAT, &ds);
    print_shmid_ds("SHM_STAT", &ds, rc);

    rc = shmctl(id, SHM_STAT_ANY, &ds);
    print_shmid_ds("SHM_STAT_ANY", &ds, rc);
end:
    puts("+++ exited with 0 +++");
    return ret;
}
