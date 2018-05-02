#ifndef NETFILTER_STRUCTS
#define NETFILTER_STRUCTS

#include "../include/shared_structs.h"

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

#endif
