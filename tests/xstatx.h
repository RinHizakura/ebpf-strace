#ifndef XSTATX_H
#define XSTATX_H

#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>

#define TEMPBUF_PIECE_SIZE 128
#define TEMPBUF_PIECE_CNT 4
#define TEMPBUF_TOTAL_SIZE (TEMPBUF_PIECE_SIZE * TEMPBUF_PIECE_CNT)

static inline size_t format_timestamp(char *buf, size_t buf_sz, long sec)
{
    time_t t = (time_t) sec;
    struct tm *tmp = localtime(&t);
    return strftime(buf, buf_sz, "%FT%T%z", tmp);
}

static inline int format_mode(char *buf, size_t buf_sz, mode_t mode)
{
    int pos = 0;

    if (S_ISREG(mode))
        pos += snprintf(buf, buf_sz, "S_IFREG");
    else if (S_ISDIR(mode))
        pos += snprintf(buf, buf_sz, "S_IFDIR");
    else if (S_ISCHR(mode))
        pos += snprintf(buf, buf_sz, "S_IFCHR");
    else if (S_ISBLK(mode))
        pos += snprintf(buf, buf_sz, "S_IFBLK");
    else
        pos += snprintf(buf, buf_sz, "%#o", mode & S_IFMT);

    pos += snprintf(buf + pos, buf_sz - pos, "|");
    pos += snprintf(buf + pos, buf_sz - pos, "%#o", mode & ~S_IFMT);

    return pos;
}

static inline void format_stat(char *buf, size_t buf_sz, struct stat *sb)
{
    char *temp_buf = malloc(TEMPBUF_TOTAL_SIZE);

    char *mode = temp_buf;
    char *atimestamp = mode + TEMPBUF_PIECE_SIZE;
    char *mtimestamp = atimestamp + TEMPBUF_PIECE_SIZE;
    char *ctimestamp = mtimestamp + TEMPBUF_PIECE_SIZE;

    format_timestamp(atimestamp, TEMPBUF_PIECE_SIZE, sb->st_atime);
    format_timestamp(mtimestamp, TEMPBUF_PIECE_SIZE, sb->st_mtime);
    format_timestamp(ctimestamp, TEMPBUF_PIECE_SIZE, sb->st_ctime);
    format_mode(mode, TEMPBUF_PIECE_SIZE, sb->st_mode);

    snprintf(buf, buf_sz,
             "{st_dev=makedev(0x%x, 0x%x), "
             "st_ino=%ld, st_mode=%s, "
             "st_nlink=%ld, st_uid=%d, st_gid=%d, "
             "st_blksize=%ld, st_blocks=%ld, st_size=%ld, "
             "st_atime=%ld /* %s */, "
             "st_mtime=%ld /* %s */, "
             "st_ctime=%ld /* %s */}",
             major(sb->st_dev), minor(sb->st_dev), sb->st_ino, mode,
             sb->st_nlink, sb->st_uid, sb->st_gid, sb->st_blksize,
             sb->st_blocks, sb->st_size, sb->st_atime, atimestamp, sb->st_mtime,
             mtimestamp, sb->st_ctime, ctimestamp);

    free(temp_buf);
}

#endif
