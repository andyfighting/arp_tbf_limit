#include <linux/types.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <net/sock.h>

#include "arp_hash.h"

#define MSG_NULL     0x0000
#define MSG_ADD      0x0100
#define MSG_DEL      0x0200
#define MSG_CLR      0x0300
#define MSG_SUCCESS  0x0400
#define MSG_FAILURE  0x0500

#define ARP_DEFENSE_TYPE (21)

typedef struct 
{
	char name[IFNAMSIZ]; //此条防御的网口名称
	u32 avg;    //每秒钟限制包数
	u32 burst;  //突发包数
}arp_cfg_t;

static spinlock_t arp_nl_lock = SPIN_LOCK_UNLOCKED;
static struct sock * arp_nl_sk;

/*
参数设置
cfg_avg:1000---------10/sec
cfg_burst:5
cfg_size:0
cfg_max:0
cfg_gc_interval:1000-----1sec
cfg_expire:10000-------10sec
*/

static int send_to_user(char * data,int len,u32 pid,u16 flags,u32 seq)
{
	int ret;
	int size;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	char * ptr;

	if (data == NULL)
	{
		len = 0;
	}
	/*计算消息总长：消息首部加上数据长度*/
	size = NLMSG_SPACE(len);
	/*分配一个新的套接字缓存*/
	skb = alloc_skb(size, GFP_ATOMIC);
	if (skb == NULL)
	{
		return -1;
	}
	/*初始化一个netlink消息首部*/\
	nlh = NLMSG_PUT(skb, 0, seq, ARP_DEFENSE_TYPE,len);/* from kernel */

	nlh->nlmsg_flags = flags;

	if (data)
	{
		/*跳过消息首部，指向数据区*/
		ptr = NLMSG_DATA(nlh);
		/*初始化数据区*/
		memset(ptr,0, len);
		/*填充待发送的数据*/
		memcpy(ptr,data,len);
		/*设置控制字段*/
	}
	NETLINK_CB(skb).dst_group = 0; /* unicast */
	/*发送数据*/
	spin_lock(&arp_nl_lock);
	ret = netlink_unicast(arp_nl_sk,skb,pid,MSG_DONTWAIT);
	spin_unlock(&arp_nl_lock);

	return 0;
nlmsg_failure:
	kfree_skb(skb);
	return -1;
}

static int init_arp_hashlimit_node(struct arp_hashlimit_node_info * node,arp_cfg_t * cfg)
{
	if(!node || !cfg )
	{
		return -1;
	}
	
	memcpy(node->name,cfg->name,IFNAMSIZ);
	node->cfg.avg = XT_HASHLIMIT_SCALE/cfg->avg;
	node->cfg.burst = cfg->burst;
	node->cfg.max = 0;
	node->cfg.size = 0;
	node->cfg.gc_interval = 1000; //垃圾回收计时器计时间隔
	node->cfg.expire = 10000; //垃圾收集时间间隔
	return 0;
}
static int rule_add(struct net * net,arp_cfg_t * arp_cfg,u32 pid)
{
	u16 ret_type = MSG_FAILURE;
	int ret = -1;	
	struct arp_hashlimit_node_info arp_cfg_node;
	init_arp_hashlimit_node(&arp_cfg_node,arp_cfg);

	printk(KERN_WARNING "##### rule_add name:%s\n",arp_cfg->name);
	printk(KERN_WARNING "arp defense add rule start\n");
	if(!add_netdev(net,&arp_cfg_node))
	{
		//printk(KERN_ERR "arp_hashlimit_check error\n");
		goto EXIT;
	}
	printk(KERN_WARNING "arp defense add rule end\n");
	ret = 0;
	ret_type = MSG_SUCCESS;
EXIT:
	send_to_user(NULL,0,pid,ret_type,0);
	return ret;
}

static int rule_del(struct net * net,arp_cfg_t * arp_cfg,u32 pid)
{
	u16 ret_type = MSG_FAILURE;
	int ret = -1;	
	printk(KERN_WARNING "##### rule_del name:%s\n",arp_cfg->name);
	printk(KERN_WARNING "arp defense del rule start\n");
	
	if (del_netdev(net,arp_cfg->name) < 0)
	{
		goto EXIT;
	}
	
	printk(KERN_WARNING "arp defense add rule end\n");
	ret = 0;
	ret_type = MSG_SUCCESS;
EXIT:
	send_to_user(NULL,0,pid,ret_type,0);
	return ret;
}

static void arp_nl_input(struct sk_buff *skb)
{
	struct net *net;
	struct nlmsghdr *nlh;
	arp_cfg_t * arp_cfg;
	u32 pid;

	printk("arp_defense netlink entry\n");

	net = sock_net(skb->sk);

	skb = skb_clone(skb,GFP_ATOMIC);
	if (skb == NULL)
	{
		return;
	}

	
	nlh = nlmsg_hdr(skb);
	pid = NETLINK_CB(skb).pid;       /* pid of sending process */

	printk("arp_defense netlink : pid %x\n",pid);
	if (skb->len < NLMSG_SPACE(0) ||
		skb->len < nlh->nlmsg_len ||
		nlh->nlmsg_len < NLMSG_SPACE(sizeof(arp_cfg_t)))
	{
		return;
	}

	arp_cfg = (arp_cfg_t *) NLMSG_DATA(nlh);

	switch (nlh->nlmsg_flags)
	{
		case MSG_NULL:
			break;
		case MSG_ADD:
			rule_add(net,arp_cfg,pid);
			break;
		case MSG_DEL:
			rule_del(net,arp_cfg,pid);
			break;
		case MSG_CLR:
			break;
		default:
			break;
	}
	kfree_skb(skb);
	return ;
}

static void arp_nl_net_exit(struct net *net)
{
	netlink_kernel_release(arp_nl_sk);
	arp_nl_sk = NULL;
}

static int arp_nl_net_init(struct net *net)
{
	struct sock *sk;
	sk = netlink_kernel_create(net,ARP_DEFENSE_TYPE, 0,
				   arp_nl_input, NULL, THIS_MODULE);
	if (sk == NULL)
		return -EAFNOSUPPORT;
	arp_nl_sk = sk;
	return 0;
}

static struct pernet_operations arp_nl_net_ops = {
	.init = arp_nl_net_init,
	.exit = arp_nl_net_exit,
};

int arp_nl_init(void)
{
	if (register_pernet_subsys(&arp_nl_net_ops))
	{
		panic("arp_nl_init: cannot initialize arp netlink\n");
		return -1;
	}
	return 0;
}

int arp_nl_exit(void)
{
	unregister_pernet_subsys(&arp_nl_net_ops);
	return 0;
}

