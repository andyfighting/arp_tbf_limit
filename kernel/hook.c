#include <linux/types.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <net/ip.h>
#include <net/net_namespace.h>
#include <net/checksum.h>
#include <linux/spinlock.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_rule.h>
#include <net/netfilter/nf_nat_protocol.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_helper.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <linux/if_ether.h>
#include <linux/if.h>

#include "arp_hook.h"
#include "arp_hash.h"
#include "arp_nl.h"

unsigned int arp_pkts_count = 0;

static struct nf_hook_ops nf_ops[] = {
	{
		.hook			= arp_pkt_input,
		.owner			= THIS_MODULE,
		.pf 			= NFPROTO_ARP,
		.hooknum		= NF_ARP_IN,
		.priority		= NF_IP_PRI_FIRST,
	},
	{
		.hook			= arp_pkt_output,
		.owner			= THIS_MODULE,
		.pf 			= NFPROTO_ARP,
		.hooknum		= NF_ARP_OUT,
		.priority		= NF_IP_PRI_LAST,
	}
};

static int  arp_module_init(void)
{
	int ret = 0;

	//need_ipv4_conntrack();

	ret = nf_register_hooks(nf_ops, ARRAY_SIZE(nf_ops));
	if (ret < 0) 
	{
		printk("arp_module_init: can't register hooks.\n");
		return -1;
	}

	if (arp_nl_init())
		goto arp_nl_init_err;
	
	if(arp_hashlimit_mt_init())
	{
		printk(KERN_ERR "arp_hashlimit: unable to create slab cache\n");
		goto arp_hashlimit_mt_init_err;
	}
	
	return ret;
arp_hashlimit_mt_init_err:
	arp_nl_exit();
arp_nl_init_err:
	nf_unregister_hooks(nf_ops, ARRAY_SIZE(nf_ops));
	return -1;
}

static void  arp_module_exit(void)
{
	nf_unregister_hooks(nf_ops, ARRAY_SIZE(nf_ops));
	arp_nl_exit();
	arp_hashlimit_mt_exit();
}

module_init(arp_module_init);
module_exit(arp_module_exit);

MODULE_LICENSE("GPL");
MODULE_ALIAS("arp_module");

