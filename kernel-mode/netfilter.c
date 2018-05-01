#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#error "unsupported kernel version"
#endif

#define LOG(format, ...) printk(KERN_INFO "[NFTI] " format "\n", ##__VA_ARGS__)


MODULE_LICENSE("license");
MODULE_AUTHOR("me");
MODULE_DESCRIPTION("traffic inspection");

static unsigned int nf_callback_out(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
    struct iphdr *ipHeader;
    struct tcphdr *tcpHeader;

    ipHeader = (struct iphdr*) skb_network_header(skb);
    if (ipHeader->protocol != IPPROTO_TCP) {
        return NF_ACCEPT;
    }

    tcpHeader = (struct tcphdr*) skb_transport_header(skb);
    if (tcpHeader->syn != 0) {
        LOG("syn on tcp pid[%d] name[%s]", current->pid, current->comm);
    }

    return NF_ACCEPT;
}

static unsigned int nf_callback_in(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
    return NF_ACCEPT;
}

static struct nf_hook_ops nf_hooks[2];

static int __init nf_init(void)
{
    int ret;

    LOG("initializing net filter module");

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
    LOG("uninitializing net filter module");

    nf_unregister_net_hook(&init_net, &nf_hooks[0]);
    nf_unregister_net_hook(&init_net, &nf_hooks[1]);

    LOG("uninitialized net filter module");
}

module_init(nf_init);
module_exit(nf_exit);
