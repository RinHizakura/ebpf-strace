#ifndef SYSCALL_ENT_H
#define SYSCALL_ENT_H

#define BUF_SIZE 32

typedef struct {
    int fd;
    u8 buf[BUF_SIZE];
    size_t count;
} read_args_t;

/* FIXME: This structure is designed to be used in
 * both C and Rust. However, this is not pretty :( */
typedef struct {
    u64 id;
    u64 ret;

    union {
        /* FIXME: We should make sure the size of every args
         * structure not extend 64 bytes */
        u8 args[64];
        read_args_t read;
    };
} syscall_ent_t;

#endif
