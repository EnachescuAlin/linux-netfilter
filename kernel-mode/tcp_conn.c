// my headers
#include "private_include/tcp_conn.h"
#include "private_include/log.h"

// linux headers
#include <linux/slab.h>

void TcpConnection_free(struct TcpConnection **conn)
{
    if (conn == NULL) {
        DLOG("warning, conn is null");
        return;
    }

    if (*conn == NULL) {
        DLOG("warning, *conn is null");
        return;
    }

    kfree(*conn);
    *conn = NULL;
}

int TcpConnection_alloc(struct TcpConnection **conn)
{
    if (conn == NULL) {
        DLOG("error, conn is null");
        return NETFILTER_ERROR_NULL_POINTER;
    }

    if (*conn != NULL) {
        DLOG("warning, *conn is not null (possible memory leak)");
    }

    *conn = kmalloc(sizeof(struct TcpConnection), GFP_ATOMIC);
    if (*conn == NULL) {
        DLOG("error, kmalloc returned null");
        return NETFILTER_ERROR_OUT_OF_MEMORY;
    }

    return NETFILTER_NO_ERROR;
}

int TcpConnection_init(struct TcpConnection *conn)
{
    if (conn == NULL) {
        DLOG("error, conn is null");
        return NETFILTER_ERROR_NULL_POINTER;
    }

    memset(conn, 0, sizeof(struct TcpConnection));

    return NETFILTER_NO_ERROR;
}

void TcpConnection_uninit(struct TcpConnection *conn)
{
    if (conn == NULL) {
        DLOG("warning, conn is null");
        return;
    }

    memset(conn, 0, sizeof(struct TcpConnection));
}
