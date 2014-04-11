#include <linux/types.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/ratelimit.h>
#include <linux/mm.h>
#include <linux/in.h>
#include <linux/ip.h>


#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/gfp.h>
#include <linux/jhash.h>

#include "arp_hash.h"
#include "../../igwlog/include/igw_log_kernel.h"

#define PKT_RECORD_LIMIT (500)
extern unsigned int arp_pkts_count;

unsigned int
arp_pkt_input(unsigned int hooknum,
          struct sk_buff *skb,
          const struct net_device *in,
          const struct net_device *out,
          int (*okfn)(struct sk_buff *))
{
	struct eth_arphdr * arp;
	u32 dst,src;
	struct netdev *inuse_node;
	char log_msg[LOG_MSG_LEN] = {0};
	char log_msg_china[LOG_MSG_LEN] = {0};

	if (!in)
	{
		goto EXIT;
	}

	inuse_node = find_netdev(in->ifindex);
	if (!inuse_node)
	{
		goto EXIT;
	}
	
	arp = (struct eth_arphdr *)arp_hdr(skb);
	if (arp->ar_hln != 6 ||
	    arp->ar_pln != 4)
	{
		goto EXIT;
	}
	
	dst = ntohl(arp->ar_tip);
	src = ntohl(arp->ar_sip);

#if 0
	printk(KERN_WARNING "arp input [1] : arp op [%x] src [%x] target [%x]\n",
		ntohs(arp->ar_op),ntohl(arp->ar_sip),ntohl(arp->ar_tip));
#endif
	if (arp->ar_op == ntohs(ARPOP_REQUEST) && !src)
	{
		goto EXIT;
	}
	if(!arp_hashlimit_mt(arp,inuse_node))//超过设定速率
	{
		arp_pkts_count++;
		//超过设定速率则丢弃arp包
		if ((net_ratelimit()) && (arp_pkts_count%PKT_RECORD_LIMIT == 0))
		{
			printk(KERN_WARNING "arp input : arp op [%x] src [%x] target [%x] ##over limit --drop##\n",
			ntohs(arp->ar_op),ntohl(arp->ar_sip),ntohl(arp->ar_tip));
			snprintf(log_msg,LOG_MSG_LEN,"[FIREWALL] arp_flood_defense drop pkts from device:%s",inuse_node->name);
			snprintf(log_msg_china,LOG_MSG_LEN,"[防火墙] ARP攻击防御丢弃从%s进入的ARP攻击包",inuse_node->name);
	        LOG(6,4,log_msg,log_msg_china);
		}
		return NF_DROP;
	}

EXIT:
	return NF_ACCEPT;
}


unsigned int
arp_pkt_output(unsigned int hooknum,
          struct sk_buff *skb,
          const struct net_device *in,
          const struct net_device *out,
          int (*okfn)(struct sk_buff *))
{
	struct eth_arphdr * arp;
	u32 dst,src;
	
	if (!out)
	{
		goto EXIT;
	}
	arp = (struct eth_arphdr *)arp_hdr(skb);
	if (arp->ar_hln != 6 ||
		arp->ar_pln != 4)
	{
		goto EXIT;
	}
	
	dst = ntohl(arp->ar_tip);
	src = ntohl(arp->ar_sip);

EXIT:
	return NF_ACCEPT;
}

