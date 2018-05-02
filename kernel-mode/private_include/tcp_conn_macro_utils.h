#ifndef NETFILTER_TCP_CONN_MACRO_UTILS
#define NETFILTER_TCP_CONN_MACRO_UTILS

#define IF_CONN_ESTABLISHED(lp) (tcpConnections[lp]->outSyn == 1 && tcpConnections[lp]->inSyn == 1)
#define IF_NO_FIN(lp) (tcpConnections[lp]->outFin == 0 && tcpConnections[lp]->inFin == 0)

#endif
