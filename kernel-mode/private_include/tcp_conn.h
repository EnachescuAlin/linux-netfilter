#ifndef NETFILTER_TCP_CONN
#define NETFILTER_TCP_CONN

#include "../include/shared_structs.h"
#include "errors.h"

struct TcpConnection
{
    struct IpAddress4 localAddress;
    struct IpAddress4 remoteAddress;
    int pid;
    char comm[16];

    __u8 outSyn : 1;
    __u8 outFin : 1;

    __u8 inSyn : 1;
    __u8 inFin : 1;
};

#define IF_CONN_ESTABLISHED(lp) (tcpConnections[lp]->outSyn == 1 && tcpConnections[lp]->inSyn == 1)
#define IF_NO_FIN(lp) (tcpConnections[lp]->outFin == 0 && tcpConnections[lp]->inFin == 0)

void TcpConnection_free(struct TcpConnection **conn);
int TcpConnection_alloc(struct TcpConnection **conn);

void TcpConnection_uninit(struct TcpConnection *conn);
int TcpConnection_init(struct TcpConnection *conn);

#endif
