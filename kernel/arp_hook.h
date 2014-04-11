#ifndef __ARP_HOOK_H__
#define __ARP_HOOK_H__

#pragma pack(1)
struct eth_arphdr
{
	__be16		ar_hrd;		/* format of hardware address	*/
	__be16		ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	__be16		ar_op;		/* ARP opcode (command)		*/

	unsigned char		ar_sha[ETH_ALEN];	/* sender hardware address	*/
	unsigned int		ar_sip;		/* sender IP address		*/
	unsigned char		ar_tha[ETH_ALEN];	/* target hardware address	*/
	unsigned int 		ar_tip;		/* target IP address		*/
};
#pragma pack()


unsigned int
arp_pkt_output(unsigned int hooknum,
          struct sk_buff *skb,
          const struct net_device *in,
          const struct net_device *out,
          int (*okfn)(struct sk_buff *));

unsigned int
arp_pkt_input(unsigned int hooknum,
          struct sk_buff *skb,
          const struct net_device *in,
          const struct net_device *out,
          int (*okfn)(struct sk_buff *));

#endif
