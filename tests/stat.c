#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static size_t format_timestamp(char *buf, size_t buf_sz, long sec)
{
    time_t t = (time_t) sec;
    struct tm *tmp = localtime(&t);
    return strftime(buf, buf_sz, "%FT%T%z", tmp);
}

static void format_stat(char *buf, size_t buf_sz, struct stat *sb)
{
    char *atimestamp = malloc(512);
    char *mtimestamp = malloc(512);
    char *ctimestamp = malloc(512);

    format_timestamp(atimestamp, 512, sb->st_atime);
    format_timestamp(mtimestamp, 512, sb->st_mtime);
    format_timestamp(ctimestamp, 512, sb->st_ctime);

    snprintf(buf, buf_sz,
             "{st_dev=makedev(0x%x, 0x%x), "
             "st_ino=%ld, st_mode=%s, "
             "st_nlink=%ld, st_uid=%d, st_gid=%d, "
             "st_blksize=%ld, st_blocks=%ld, st_size=%ld, "
             "st_atime=%ld /* %s */, "
             "st_mtime=%ld /* %s */, "
             "st_ctime=%ld /* %s */}",
             major(sb->st_dev), minor(sb->st_dev), sb->st_ino,
             "S_IFREG|0664",  // FIXME: don't hardcode this
             sb->st_nlink, sb->st_uid, sb->st_gid, sb->st_blksize,
             sb->st_blocks, sb->st_size, sb->st_atime, atimestamp, sb->st_mtime,
             mtimestamp, sb->st_ctime, ctimestamp);

    free(atimestamp);
    free(mtimestamp);
    free(ctimestamp);
}

int main()
{
    int ret = 0;

    const char *sample = "tests/sample.txt";
    struct stat sb;

    int rslt = syscall(SYS_stat, sample, &sb);
    if (rslt == -1) {
        ret = -1;
        goto end;
    }
    char sb_str[512] = {0};
    format_stat(sb_str, 512, &sb);
    printf("stat(\"%s\", %s) = %d\n", sample, sb_str, rslt);

    rslt = syscall(SYS_lstat, sample, &sb);
    if (rslt == -1) {
        ret = -1;
        goto end;
    }
    format_stat(sb_str, 512, &sb);
    printf("lstat(\"%s\", %s) = %d\n", sample, sb_str, rslt);

    int fd = open(sample, O_RDONLY);
    if (fd < 0) {
        ret = -1;
        goto end;
    }
    rslt = syscall(SYS_fstat, fd, &sb);
    if (rslt == -1) {
        close(fd);
        ret = -1;
        goto end;
    }
    format_stat(sb_str, 512, &sb);
    printf("fstat(%d, %s) = %d\n", fd, sb_str, rslt);

    close(fd);
end:
    puts("+++ exited with 0 +++");
    return ret;
}
