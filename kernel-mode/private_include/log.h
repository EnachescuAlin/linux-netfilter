#ifndef NETFILTER_LOG
#define NETFILTER_LOG

#ifdef MODULE_DEBUG
#define DLOG(format, ...) printk(KERN_INFO "[Debug-NFTI] [%s] " format "\n", __FUNCTION__, ##__VA_ARGS__)
#else
#define DLOG(format, ...)
#endif

#define LOG(format, ...) printk(KERN_INFO "[NFTI] [%s] " format "\n", __FUNCTION__, ##__VA_ARGS__)

#define LOG_TCP_CONNECTION_FORMAT " outFin[%d], inFin[%d], outSyn[%d], inSyn[%d]"
#define LOG_TCP_CONNECTION(localPort)           \
    (int) tcpConnections[localPort]->outFin,    \
    (int) tcpConnections[localPort]->inFin,     \
    (int) tcpConnections[localPort]->outSyn,    \
    (int) tcpConnections[localPort]->inSyn

#endif
