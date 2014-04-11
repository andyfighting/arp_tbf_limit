#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/mm.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <net/net_namespace.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter/xt_hashlimit.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>

#include "arp_hash.h"
#include "arp_hook.h"


#define HASH_TBL_SIZE (256)
struct hash_tbl netdev_tbl;

#define netdev_hash(ifindex) ((ifindex)%HASH_TBL_SIZE)
#define hash_node_to_dev(node) (hash_node_entry((node),struct netdev,netdev_list))


static DEFINE_SPINLOCK(hashlimit_lock);	/* protects htables list */
static DEFINE_MUTEX(hlimit_mutex);	/* additional checkentry protection */
static struct kmem_cache *hashlimit_cachep __read_mostly;

static inline bool dst_cmp(const struct dsthash_ent *ent,
			   const struct dsthash_dst *b)
{
	return !memcmp(&ent->dst, b, sizeof(ent->dst));
}

/*	使用jhash2来计算hashkey
	 * Instead of returning hash % ht->cfg.size (implying a divide)
	 * we return the high 32 bits of the (hash * ht->cfg.size) that will
	 * give results between [0 and cfg.size-1] and same hash distribution,
	 * but using a multiply, less expensive than a divide
*/
static u_int32_t hash_dst(const struct netdev *ht, const struct dsthash_dst *dst)
{
	u_int32_t hash = jhash2((const u32 *)dst,
				sizeof(*dst)/sizeof(u32),
				ht->rnd);
	return ((u64)hash * ht->cfg.size) >> 32;
}

static struct dsthash_ent * dsthash_find(const struct netdev *ht,const struct dsthash_dst *dst)
{
	struct dsthash_ent *ent;
	struct hlist_node *pos;
	u_int32_t hash = hash_dst(ht, dst);
	
	if (!hlist_empty(&ht->hash[hash])) 
	{
		hlist_for_each_entry(ent, pos, &ht->hash[hash], node)
		{		
			if (dst_cmp(ent, dst))
				return ent;
		}
	}
	return NULL;
}

/* allocate dsthash_ent, initialize dst, put in htable and lock it */
static struct dsthash_ent * dsthash_alloc_init(struct netdev *ht,const struct dsthash_dst *dst)
{
	struct dsthash_ent *ent;
	/*新增rule初次初始化 */
	if (!ht->rnd_initialized) 
	{
		get_random_bytes(&ht->rnd, sizeof(ht->rnd));
		ht->rnd_initialized = 1;
	}

	if (ht->cfg.max && ht->count >= ht->cfg.max) 
	{
		if (net_ratelimit())
			printk(KERN_WARNING "arp_hashlimit: max count of %u reached\n",ht->cfg.max);
		return NULL;
	}
	ent = kmem_cache_alloc(hashlimit_cachep, GFP_ATOMIC);
	if (!ent) 
	{
		if (net_ratelimit())
			printk(KERN_ERR "arp_hashlimit: can't allocate dsthash_ent\n");
		return NULL;
	}
	memcpy(&ent->dst, dst, sizeof(ent->dst));
	hlist_add_head(&ent->node, &ht->hash[hash_dst(ht, dst)]);
	ht->count++;
	return ent;
}

static inline void
dsthash_free(struct netdev *ht, struct dsthash_ent *ent)
{
	hlist_del(&ent->node);
	kmem_cache_free(hashlimit_cachep, ent);
	ht->count--;
}
static void htable_gc(unsigned long htlong);

static bool select_all(const struct netdev *ht,const struct dsthash_ent *he)
{
	return 1;
}
static bool select_gc(const struct netdev *ht,const struct dsthash_ent *he)
{
	return time_after_eq(jiffies, he->expires);
}

static void htable_selective_cleanup(struct netdev *ht,
										 bool (*select)(const struct netdev *ht,
				     					 const struct dsthash_ent *he))
{
	unsigned int i;
	spin_lock_bh(&ht->lock);
	for (i = 0; i < ht->cfg.size; i++) 
	{
		struct dsthash_ent *dh;
		struct hlist_node *pos, *n;
		
		if (!hlist_empty(&ht->hash[i]))
		{
			hlist_for_each_entry_safe(dh, pos, n, &ht->hash[i], node) 
			{	
				if ((*select)(ht, dh))
				dsthash_free(ht, dh);
			}
		}
	}
	spin_unlock_bh(&ht->lock);
}

static void htable_gc(unsigned long htlong)
{
	struct netdev *ht = (struct netdev *)htlong;
	htable_selective_cleanup(ht, select_gc);
	/* re-add the timer accordingly */
	ht->timer.expires = jiffies + msecs_to_jiffies(ht->cfg.gc_interval);
	add_timer(&ht->timer);
}

/* TBF算法实现
 * see net/sched/sch_tbf.c in the linux source tree
 */

#define MAX_CPJ (0xFFFFFFFF / (HZ*60*60*24))

/* Repeated shift and or gives us all 1s, final shift and add 1 gives
 * us the power of 2 below the theoretical max, so GCC simply does a
 * shift. */
#define _POW2_BELOW2(x) ((x)|((x)>>1))
#define _POW2_BELOW4(x) (_POW2_BELOW2(x)|_POW2_BELOW2((x)>>2))
#define _POW2_BELOW8(x) (_POW2_BELOW4(x)|_POW2_BELOW4((x)>>4))
#define _POW2_BELOW16(x) (_POW2_BELOW8(x)|_POW2_BELOW8((x)>>8))
#define _POW2_BELOW32(x) (_POW2_BELOW16(x)|_POW2_BELOW16((x)>>16))
#define POW2_BELOW32(x) ((_POW2_BELOW32(x)>>1) + 1)

#define CREDITS_PER_JIFFY POW2_BELOW32(MAX_CPJ)

/* Precision saver. */
static inline u_int32_t
user2credits(u_int32_t user)
{
	/* If multiplying would overflow... */
	if (user > 0xFFFFFFFF / (HZ*CREDITS_PER_JIFFY))
		/* Divide first. */
		return (user / XT_HASHLIMIT_SCALE) * HZ * CREDITS_PER_JIFFY;

	return (user * HZ * CREDITS_PER_JIFFY) / XT_HASHLIMIT_SCALE;
}

static inline void rateinfo_recalc(struct dsthash_ent *dh, unsigned long now)
{
	dh->rateinfo.credit += (now - dh->rateinfo.prev) * CREDITS_PER_JIFFY;
	if (dh->rateinfo.credit > dh->rateinfo.credit_cap)
		dh->rateinfo.credit = dh->rateinfo.credit_cap;
	dh->rateinfo.prev = now;
}

static int
hashlimit_init_dst(struct dsthash_dst *dst,struct eth_arphdr * arp)
{
	memset(dst, 0, sizeof(*dst));
	dst->src_ip = ntohl(arp->ar_sip);
	memcpy(dst->src_mac,arp->ar_sha,ETH_ALEN);
	return 0;
}

bool arp_hashlimit_mt(struct eth_arphdr *arp, struct netdev *hinfo)
{
	unsigned long now = jiffies;
	struct dsthash_ent *dh;
	struct dsthash_dst dst;

	if (hashlimit_init_dst(&dst, arp) < 0)
		goto hotdrop;

	spin_lock_bh(&hinfo->lock);
	dh = dsthash_find(hinfo, &dst);
	if (dh == NULL) 
	{
		dh = dsthash_alloc_init(hinfo, &dst);
		if (dh == NULL) 
		{
			spin_unlock_bh(&hinfo->lock);
			goto hotdrop;
		}

		dh->expires = jiffies + msecs_to_jiffies(hinfo->cfg.expire);
		dh->rateinfo.prev = jiffies;
		dh->rateinfo.credit = user2credits(hinfo->cfg.avg *
		                      hinfo->cfg.burst);
		dh->rateinfo.credit_cap = user2credits(hinfo->cfg.avg *
		                          hinfo->cfg.burst);
		dh->rateinfo.cost = user2credits(hinfo->cfg.avg);
	} 
	else 
	{
		/* 重新计算令牌数 */
		dh->expires = now + msecs_to_jiffies(hinfo->cfg.expire);
		rateinfo_recalc(dh, now);
	}

	if (dh->rateinfo.credit >= dh->rateinfo.cost) 
	{
		/* 在设定速率之下 */
		dh->rateinfo.credit -= dh->rateinfo.cost;
		spin_unlock_bh(&hinfo->lock);
		return true;
	}

	spin_unlock_bh(&hinfo->lock);
	/* default match is underlimit - so over the limit, we need to invert */
	return false;

 hotdrop:
	return false;
}

static void __dep_del_netdev(struct netdev * dev)
{
	del_timer_sync(&dev->timer);
	htable_selective_cleanup(dev, select_all);
	kfree(dev);//vfree(dev)改用连续内存释放kfree	
}
static void __del_netdev(struct netdev * dev)
{
	if (atomic_dec_and_test(&dev->use)) 
	{
			spin_lock_bh(&hashlimit_lock);
			del_from_hash_tbl(&netdev_tbl,&dev->netdev_list);
			spin_unlock_bh(&hashlimit_lock);
			udelay(15000);
			__dep_del_netdev(dev);
	}	
}

static int del_netdev_callback(struct hash_node * node,void * data)
{
	struct netdev * dev;
	dev = hash_node_to_dev(node);

	__del_from_hash_tbl(&dev->netdev_list);
	udelay(15000);
	__dep_del_netdev(dev);
	return 0;
}

static void * netdev_cmp(struct hash_node * node,void * data)
{
	struct netdev * dev;
	int ifindex;
	dev = hash_node_to_dev(node);

	ifindex = (int)data;
	if (dev->ifindex == ifindex)
	{
		return (void *)dev;
	}
	return NULL;
}

int init_netdev_tbl(void)
{
	return init_hash_tbl(&netdev_tbl,HASH_TBL_SIZE);
}

int destroy_netdev_tbl(void)
{
	return destroy_hash_tbl(&netdev_tbl,del_netdev_callback,NULL);
}

int  __add_netdev__(int ifindex , struct arp_hashlimit_node_info *minfo)
{
	struct netdev * dev;
	unsigned int size;
	unsigned int i;
	
	if (minfo->cfg.size) 
	{
		size = minfo->cfg.size;
	} 
	else 
	{
		size = (totalram_pages << PAGE_SHIFT) / 16384 /
		       sizeof(struct list_head);
		if (totalram_pages > 1024 * 1024 * 1024 / PAGE_SIZE)
			size = 8192;
		if (size < 16)
			size = 16;
	}

	//改用连续内存空间kmalloc --dev = vmalloc(sizeof(struct netdev) +sizeof(struct list_head) * size);
	dev = (struct netdev *)kmalloc(sizeof(struct netdev) + sizeof(struct list_head) * size,GFP_ATOMIC);

	if (dev == NULL)
	{
		printk(KERN_ERR "arp_hashlimit: unable to create hashtable\n");
		return -1;
	}
	memset(dev,0,(sizeof(struct netdev) + sizeof(struct list_head) * size));

	memcpy(&dev->cfg, &minfo->cfg, sizeof(dev->cfg));
	dev->cfg.size = size;
	if(dev->cfg.max == 0)
	{
		dev->cfg.max = 8 * dev->cfg.size;
	}
	else if(dev->cfg.max < dev->cfg.size)
	{
		dev->cfg.max = dev->cfg.size;
	}

	for (i = 0; i < dev->cfg.size; i++)
	{
		INIT_HLIST_HEAD(&dev->hash[i]);
	}
	dev->ifindex = ifindex;
	atomic_set(&dev->use, 1);
	dev->count = 0;
	dev->rnd_initialized = 0;
	spin_lock_init(&dev->lock);
	strncpy(dev->name,minfo->name,IFNAMSIZ);

	setup_timer(&dev->timer, htable_gc, (unsigned long)dev);
	dev->timer.expires = jiffies + msecs_to_jiffies(dev->cfg.gc_interval);
	add_timer(&dev->timer);

	spin_lock_bh(&hashlimit_lock);
	add_to_hash_tbl(&netdev_tbl,&dev->netdev_list,netdev_hash(ifindex));
	spin_unlock_bh(&hashlimit_lock);

	return 0;
}

bool add_netdev(struct net * net,struct arp_hashlimit_node_info *info)
{
	struct net_device * netdev = NULL;
	struct netdev * dev;
	int ifindex = 0;
	
	/* 检查传入的node info是否合法 */
	if (info->cfg.burst == 0 ||
	    user2credits(info->cfg.avg * info->cfg.burst) <
	    user2credits(info->cfg.avg)) 
	{
		printk(KERN_ERR "arp_hashlimit: overflow, try lower: %u/%u\n",
		       info->cfg.avg, info->cfg.burst);
		return false;
	}
	if (info->cfg.gc_interval == 0 || info->cfg.expire == 0)
		return false;
	if (info->name[sizeof(info->name)-1] != '\0')
		return false;
	
	netdev = dev_get_by_name(net,info->name);
	if (netdev == NULL)
	{
		return false;
	}
	ifindex = netdev->ifindex;
	dev_put(netdev);

	mutex_lock(&hlimit_mutex);

	dev = find_netdev(ifindex);
	if(dev)
	{
		mutex_unlock(&hlimit_mutex);
		return false;
	}
	if(__add_netdev__(ifindex,info))
	{
		mutex_unlock(&hlimit_mutex);
		return false;
	}
	mutex_unlock(&hlimit_mutex);
	return true;
}

struct netdev * find_netdev(int ifindex)
{
	return (struct netdev *)find_from_hash_tbl(&netdev_tbl,netdev_hash(ifindex),netdev_cmp,(void *)ifindex);
}

int del_netdev(struct net * net,char * name)
{
	struct net_device * netdev = NULL;
	struct netdev * dev;
	
	int ifindex = 0;
	netdev = dev_get_by_name(net,name);
	if (netdev == NULL)
	{
		return -1;
	}
	ifindex = netdev->ifindex;
	dev_put(netdev);

	dev = find_netdev(ifindex);
	if (dev == NULL)
	{
		return -1;
	}
	__del_netdev(dev);
	return 0;
}


int  arp_hashlimit_mt_init(void)
{
	int err;
	printk(KERN_WARNING "[arp_hashlimit] hashlimit_mt_init\n");
	err = -ENOMEM;
	hashlimit_cachep = kmem_cache_create("arp_hashlimit",
					    sizeof(struct dsthash_ent), 0, 0,
					    NULL);
	if (!hashlimit_cachep) 
	{
		printk(KERN_ERR "arp_hashlimit: unable to create slab cache\n");
		goto err1;
	}
	init_netdev_tbl();
	err = 0;
err1:
	return err;
}

void arp_hashlimit_mt_exit(void)
{
	kmem_cache_destroy(hashlimit_cachep);
	destroy_netdev_tbl();
	printk(KERN_WARNING "[arp_hashlimit] hashlimit_mt_exit\n");
}

