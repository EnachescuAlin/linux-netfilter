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
        printk(KERN_INFO "syn on tcp pid[%d] name[%s]\n", current->pid, current->comm);
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

    printk(KERN_INFO "initializing net filter module\n");

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
        printk(KERN_INFO "nf_register_net_hook (in) failed [%d]\n", ret);
        return ret;
    }

    ret = nf_register_net_hook(&init_net, &nf_hooks[1]);
    if (ret < 0) {
        nf_unregister_net_hook(&init_net, &nf_hooks[0]);

        printk(KERN_INFO "nf_register_net_hook (out) failed [%d]\n", ret);
        return ret;
    }

    printk(KERN_INFO "initialized successfully\n");
    return 0;
}

static void __exit nf_exit(void)
{
    printk(KERN_INFO "uninitializing net filter module\n");

    nf_unregister_net_hook(&init_net, &nf_hooks[0]);
    nf_unregister_net_hook(&init_net, &nf_hooks[1]);

    printk(KERN_INFO "uninitialized net filter module\n");
}

module_init(nf_init);
module_exit(nf_exit);
