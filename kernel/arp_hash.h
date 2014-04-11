#ifndef _ARP_HASH_H_
#define _ARP_HASH_H_

#include <linux/types.h>
#include "arp_hook.h"

#include <linux/types.h>
#include <linux/mempool.h>
#include <linux/spinlock.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/net_namespace.h>
#include "hash_tbl.h"

/* timings are in milliseconds. */
#define XT_HASHLIMIT_SCALE 10000
/* 1/10,000 sec period => max of 10,000/sec.  Min rate is then 429490
   seconds, or one every 59 hours. */

/* details of this structure hidden by the implementation */
//struct arp_hashlimit_htable;

/* hash table crap */
struct dsthash_dst {
	unsigned char		src_mac[ETH_ALEN];
	unsigned int		src_ip;
	/*unsigned char		dst_mac[ETH_ALEN];*/
	/*unsigned int 		dst_ip;*/
};

struct dsthash_ent {
	/* static / read-only parts in the beginning */
	struct hlist_node node;
	struct dsthash_dst dst;

	/* modified structure members in the end */
	unsigned long expires;		/* precalculated expiry time */
	struct {
		unsigned long prev;	/* last modification */
		u_int32_t credit;
		u_int32_t credit_cap, cost;
	} rateinfo;
};

struct arp_hashlimit_cfg {
	/*__u32 mode;	   bitmask of XT_HASHLIMIT_HASH_* */
	__u32 avg;    /* Average secs between packets * scale */
	__u32 burst;  /* Period multiplier for upper limit. */

	/* user specified */
	__u32 size;		/* how many buckets */
	__u32 max;		/* max number of entries */
	__u32 gc_interval;	/* gc interval */
	__u32 expire;	/* when do entries expire? */
};

struct netdev
{
	struct hash_node netdev_list;
	char   name[IFNAMSIZ];
	int    ifindex;
	//struct hlist_node node;		/* global list of all htables */
	atomic_t use;
	struct arp_hashlimit_cfg cfg;	/* config */

	/* used internally */
	spinlock_t lock;		/* lock for list_head */
	u_int32_t rnd;			/* random seed for hash */
	int rnd_initialized;
	unsigned int count;		/* number entries in table */
	struct timer_list timer;	/* timer for gc */

	//struct hlist_head hash[0];	/* hashtable itself */
	struct hlist_head hash[0];	/* hashtable itself */
};


struct arp_hashlimit_node_info{
	char name[IFNAMSIZ];
	struct arp_hashlimit_cfg cfg;
};

int  arp_hashlimit_mt_init(void);
void arp_hashlimit_mt_exit(void);

bool arp_hashlimit_mt(struct eth_arphdr *arp, struct netdev *hinfo);

int  __add_netdev__(int ifindex , struct arp_hashlimit_node_info *minfo);
bool add_netdev(struct net * net,struct arp_hashlimit_node_info *info);
struct netdev * find_netdev(int ifindex);
int del_netdev(struct net * net,char * name);
int init_netdev_tbl(void);
int destroy_netdev_tbl(void);


#endif /*_ARP_HASH_H*/

