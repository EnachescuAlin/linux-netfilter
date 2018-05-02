// linux header
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/version.h>

// net headers
#include <net/netfilter/nf_queue.h>

#define MODULE_DEBUG

// my headers
#include "include/shared_structs.h"
#include "private_include/log.h"
#include "private_include/structs.h"
#include "private_include/tcp_conn_macro_utils.h"

// check linux version...
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#error "unsupported kernel version"
#endif

// about module
MODULE_LICENSE("license");
MODULE_AUTHOR("me");
MODULE_DESCRIPTION("traffic inspection");

#define MAX_NUM_TCP_CONNS 65536
static struct TcpConnection* tcpConnections[MAX_NUM_TCP_CONNS];

static void freeTcpConnection(__u16 localPort)
{
    // TODO: drop packets
    kfree(tcpConnections[localPort]);
    tcpConnections[localPort] = NULL;
}

static unsigned int nf_callback_out(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
    struct iphdr *ipHeader;
    struct tcphdr *tcpHeader;
    __u16 localPort;
    struct TcpConnection *conn = NULL;

    ipHeader = (struct iphdr*) skb_network_header(skb);
    if (ipHeader->protocol != IPPROTO_TCP) {
        return NF_ACCEPT;
    }

    tcpHeader = (struct tcphdr*) skb_transport_header(skb);
    localPort = ntohs(tcpHeader->source);

    if (tcpHeader->syn != 0) {
        if (tcpConnections[localPort] != NULL) {
            // drop packet if we did not received a fin from any direction and
            // we received syn from the both directions
            if (IF_NO_FIN(localPort) && IF_CONN_ESTABLISHED(localPort)) {
                return NF_DROP;
            }

            // drop current tcp connection
            LOG("info, we received out syn and tcp connection is not null" LOG_TCP_CONNECTION_FORMAT ", localPort[%hu]",
                LOG_TCP_CONNECTION(localPort), localPort);
            freeTcpConnection(localPort);
        }

        tcpConnections[localPort] = (struct TcpConnection*) kmalloc(sizeof(struct TcpConnection), GFP_ATOMIC);
        memset(tcpConnections[localPort], 0, sizeof(struct TcpConnection));

        conn = tcpConnections[localPort];

        conn->localAddress.port = ntohs(tcpHeader->source);
        conn->localAddress.ip = 0;

        conn->remoteAddress.port = ntohs(tcpHeader->dest);
        conn->remoteAddress.ip = 0;

        conn->pid = current->pid;
        memcpy(conn->comm, current->comm, 16);

        conn->outSyn = 1;

        return NF_ACCEPT;
    } else if (tcpHeader->rst != 0) {
        // if we receive rst then drop the connection
        if (tcpConnections[localPort] != NULL) {
            LOG("info, out rst => drop connection localPort[%hu]", localPort);
            freeTcpConnection(localPort);
        } else {
            DLOG("warning, receive out rst and conn is null localPort[%hu]", localPort);
        }
    } else if (tcpHeader->fin != 0) {
    }

    // data

    return NF_ACCEPT;
}

static unsigned int nf_callback_in(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
    struct iphdr *ipHeader;
    struct tcphdr *tcpHeader;
    __u16 localPort;

    ipHeader = (struct iphdr*) skb_network_header(skb);
    if (ipHeader->protocol != IPPROTO_TCP) {
        return NF_ACCEPT;
    }

    tcpHeader = (struct tcphdr*) skb_transport_header(skb);
    localPort = ntohs(tcpHeader->dest);

    if (tcpHeader->syn != 0) {
        if (tcpConnections[localPort] == NULL) {
            LOG("warning, tcp connection is null localPort[%hu]", localPort);
            return NF_ACCEPT;
        }

        tcpConnections[localPort]->inSyn = 1;

        DLOG("info, connection established localPort[%hu]", localPort);

        // send to user mode that a connection was established

        return NF_ACCEPT;
    } else if (tcpHeader->rst != 0) {
    } else if (tcpHeader->fin != 0) {
    }

    // data

    return NF_ACCEPT;
}

static struct nf_hook_ops nf_hooks[2];

static int __init nf_init(void)
{
    int ret;

    LOG("initializing net filter module");

    memset(tcpConnections, 0, sizeof(tcpConnections));

    memset(nf_hooks, 0, sizeof(nf_hooks));

    // in
    nf_hooks[0].hook     = (nf_hookfn*) nf_callback_in,
    nf_hooks[0].pf       = PF_INET,
    nf_hooks[0].hooknum  = NF_INET_LOCAL_IN,
    nf_hooks[0].priority = NF_IP_PRI_FIRST,

    // out
    nf_hooks[1].hook     = (nf_hookfn*) nf_callback_out,
    nf_hooks[1].pf       = PF_INET,
    nf_hooks[1].hooknum  = NF_INET_LOCAL_OUT,
    nf_hooks[1].priority = NF_IP_PRI_FIRST,

    ret = nf_register_net_hook(&init_net, &nf_hooks[0]);
    if (ret < 0) {
        LOG("nf_register_net_hook (in) failed [%d]", ret);
        return ret;
    }

    ret = nf_register_net_hook(&init_net, &nf_hooks[1]);
    if (ret < 0) {
        nf_unregister_net_hook(&init_net, &nf_hooks[0]);

        LOG("nf_register_net_hook (out) failed [%d]", ret);
        return ret;
    }

    LOG("initialized successfully");
    return 0;
}

static void __exit nf_exit(void)
{
    int i;

    LOG("uninitializing net filter module");

    nf_unregister_net_hook(&init_net, &nf_hooks[0]);
    nf_unregister_net_hook(&init_net, &nf_hooks[1]);

    // todo free memory
    for (i = 0; i < MAX_NUM_TCP_CONNS; i++) {
        if (tcpConnections[i] != NULL) {
            kfree(tcpConnections[i]);
        }
    }

    LOG("uninitialized net filter module");
}

module_init(nf_init);
module_exit(nf_exit);
