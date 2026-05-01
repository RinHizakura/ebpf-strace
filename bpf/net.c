static void sys_socket_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int domain = (int) parms.parm1;
    int type = (int) parms.parm2;
    int protocol = (int) parms.parm3;

    socket_args_t *socket = (socket_args_t *) ent->bytes;
    socket->domain = domain;
    socket->type = type;
    socket->protocol = protocol;
}

static void sys_connect_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int sockfd = (int) parms.parm1;
    void *addr = (void *) parms.parm2;
    u32 addrlen = (u32) parms.parm3;

    connect_args_t *connect = (connect_args_t *) ent->bytes;
    connect->sockfd = sockfd;
    connect->addrlen = addrlen;

    memset(connect->addr, 0, sizeof(connect->addr));
    if (addr) {
        u32 cpy_len =
            addrlen > sizeof(connect->addr) ? sizeof(connect->addr) : addrlen;
        bpf_core_read_user(connect->addr, cpy_len, addr);
    }
}

static void sys_accept_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int sockfd = (int) parms.parm1;
    void *addr = (void *) parms.parm2;
    void *addrlen_ptr = (void *) parms.parm3;

    accept_args_t *accept = (accept_args_t *) ent->bytes;
    accept->sockfd = sockfd;
    accept->addrlen = 0;
    accept->initial_addrlen = 0;
    if (addrlen_ptr)
        bpf_core_read_user(&accept->initial_addrlen,
                           sizeof(accept->initial_addrlen), addrlen_ptr);

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf0 != NULL)
        *buf0 = addr;
    void **buf1 = bpf_g_buf_addr_lookup_elem(&INDEX_1);
    if (buf1 != NULL)
        *buf1 = addrlen_ptr;
}

static void sys_accept_exit(syscall_ent_t *ent)
{
    accept_args_t *accept = (accept_args_t *) ent->bytes;
    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    void **buf1 = bpf_g_buf_addr_lookup_elem(&INDEX_1);

    memset(accept->addr, 0, sizeof(accept->addr));
    if (buf1 != NULL && *buf1 != NULL)
        bpf_core_read_user(&accept->addrlen, sizeof(accept->addrlen), *buf1);
    if (buf0 != NULL && *buf0 != NULL) {
        u32 cpy_len = accept->addrlen > sizeof(accept->addr)
                          ? sizeof(accept->addr)
                          : accept->addrlen;
        bpf_core_read_user(accept->addr, cpy_len, *buf0);
    }
}

static void sys_accept4_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int sockfd = (int) parms.parm1;
    void *addr = (void *) parms.parm2;
    void *addrlen_ptr = (void *) parms.parm3;
    int flags = (int) parms.parm4;

    accept4_args_t *accept4 = (accept4_args_t *) ent->bytes;
    accept4->sockfd = sockfd;
    accept4->flags = flags;
    accept4->addrlen = 0;
    accept4->initial_addrlen = 0;
    if (addrlen_ptr)
        bpf_core_read_user(&accept4->initial_addrlen,
                           sizeof(accept4->initial_addrlen), addrlen_ptr);

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf0 != NULL)
        *buf0 = addr;
    void **buf1 = bpf_g_buf_addr_lookup_elem(&INDEX_1);
    if (buf1 != NULL)
        *buf1 = addrlen_ptr;
}

static void sys_accept4_exit(syscall_ent_t *ent)
{
    accept4_args_t *accept4 = (accept4_args_t *) ent->bytes;
    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    void **buf1 = bpf_g_buf_addr_lookup_elem(&INDEX_1);

    memset(accept4->addr, 0, sizeof(accept4->addr));
    if (buf1 != NULL && *buf1 != NULL)
        bpf_core_read_user(&accept4->addrlen, sizeof(accept4->addrlen), *buf1);
    if (buf0 != NULL && *buf0 != NULL) {
        u32 cpy_len = accept4->addrlen > sizeof(accept4->addr)
                          ? sizeof(accept4->addr)
                          : accept4->addrlen;
        bpf_core_read_user(accept4->addr, cpy_len, *buf0);
    }
}

static void sys_sendto_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int sockfd = (int) parms.parm1;
    void *buf = (void *) parms.parm2;
    size_t len = (size_t) parms.parm3;
    int flags = (int) parms.parm4;
    void *dest_addr = (void *) parms.parm5;
    u32 addrlen = (u32) parms.parm6;

    sendto_args_t *sendto = (sendto_args_t *) ent->bytes;
    sendto->sockfd = sockfd;
    sendto->len = len;
    sendto->flags = flags;
    sendto->addrlen = addrlen;
    sendto->is_addr_exist = (dest_addr != NULL);

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf0 != NULL)
        *buf0 = buf;

    memset(sendto->dest_addr, 0, sizeof(sendto->dest_addr));
    if (dest_addr) {
        u32 alen = addrlen > sizeof(sendto->dest_addr)
                       ? sizeof(sendto->dest_addr)
                       : addrlen;
        bpf_core_read_user(sendto->dest_addr, alen, dest_addr);
    }
}

static void sys_sendto_exit(syscall_ent_t *ent)
{
    sendto_args_t *sendto = (sendto_args_t *) ent->bytes;
    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    memset(sendto->buf, 0, sizeof(sendto->buf));
    if (buf0 != NULL && *buf0 != NULL) {
        u32 cpy_len = sendto->len > sizeof(sendto->buf) ? sizeof(sendto->buf)
                                                        : (u32) sendto->len;
        bpf_core_read_user(sendto->buf, cpy_len, *buf0);
    }
}

static void sys_recvfrom_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int sockfd = (int) parms.parm1;
    void *buf = (void *) parms.parm2;
    size_t len = (size_t) parms.parm3;
    int flags = (int) parms.parm4;
    void *src_addr = (void *) parms.parm5;

    recvfrom_args_t *recvfrom = (recvfrom_args_t *) ent->bytes;
    recvfrom->sockfd = sockfd;
    recvfrom->len = len;
    recvfrom->flags = flags;
    recvfrom->src_addrlen = 0;
    recvfrom->is_addr_exist = (src_addr != NULL);

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf0 != NULL)
        *buf0 = buf;
    void **buf1 = bpf_g_buf_addr_lookup_elem(&INDEX_1);
    if (buf1 != NULL)
        *buf1 = src_addr;
}

static void sys_recvfrom_exit(syscall_ent_t *ent)
{
    recvfrom_args_t *recvfrom = (recvfrom_args_t *) ent->bytes;
    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    void **buf1 = bpf_g_buf_addr_lookup_elem(&INDEX_1);

    memset(recvfrom->buf, 0, sizeof(recvfrom->buf));
    if (buf0 != NULL && *buf0 != NULL) {
        size_t cpy_len = recvfrom->len > sizeof(recvfrom->buf)
                             ? sizeof(recvfrom->buf)
                             : recvfrom->len;
        bpf_core_read_user(recvfrom->buf, cpy_len, *buf0);
    }

    memset(recvfrom->src_addr, 0, sizeof(recvfrom->src_addr));
    if (buf1 != NULL && *buf1 != NULL) {
        recvfrom->src_addrlen = sizeof(recvfrom->src_addr);
        bpf_core_read_user(recvfrom->src_addr, sizeof(recvfrom->src_addr),
                           *buf1);
    }
}
