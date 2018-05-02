#ifndef NETFILTER_SHARED_STRUCTS
#define NETFILTER_SHARED_STRUCTS

#include <linux/types.h>

struct IpAddress4
{
    __u16 port;
    __u32 ip;
};

enum Direction
{
    in = 0,
    out
};

enum EventType
{
    syn = 0,
    data,
    fin,
    rst
};

struct SynEvent
{
    struct IpAddress4 localAddress;
    struct IpAddress4 remoteAddress;
    int pid;
    char procName[16];
};

struct FinEvent
{
    __u16 localPort;
    enum Direction direction;
};

struct RstEvent
{
    __u16 localPort;
    enum Direction direction;
};

struct DataEvent
{
    __u16 localPort;
    enum Direction direction;
    __u32 dataLength;
    __u8 data[1];
};

struct Event
{
    enum EventType type;
    union
    {
        struct SynEvent syn;
        struct DataEvent data;
        struct FinEvent fin;
        struct RstEvent rst;
    };
};

#endif
