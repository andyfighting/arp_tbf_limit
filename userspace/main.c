#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/if.h>
#include <linux/types.h>
#include <arpa/inet.h>


#define NAME_SIZE 64
#define MSG_NULL     0x0000
#define MSG_ADD      0x0100
#define MSG_DEL      0x0200
#define MSG_CLR      0x0300
#define MSG_SUCCESS  0x0400
#define MSG_FAILURE  0x0500

#define ARP_DEFENSE_TYPE (21)

typedef unsigned short u16;
typedef unsigned int u32;

typedef struct 
{
	char name[IFNAMSIZ]; //此条防御的名称
	u32 avg;    //每秒钟限制包数
	u32 burst;  //突发包数
}arp_cfg_t;

struct msg_to_kernel
{
	struct nlmsghdr hdr;
	arp_cfg_t data;
};

int skfd = -1;

int create_nl(u16 type)
{
	int fd;	
	struct sockaddr_nl local;
	
	fd = socket(PF_NETLINK, SOCK_RAW, type);
	if (fd < 0)
	{
		printf("can not create a netlink socket\n");
		return -1;
	}
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();
	local.nl_groups = 0;
	if(bind(fd, (struct sockaddr*)&local, sizeof(local)) != 0)
	{
		printf("bind() error\n");
		return -1;
	}
	return fd;
}

int send_to_kernel(void * data,int len)
{
	struct sockaddr_nl kpeer;

	memset(&kpeer, 0, sizeof(kpeer));
	kpeer.nl_family = AF_NETLINK;
	kpeer.nl_pid = 0;
	kpeer.nl_groups = 0;

	sendto(skfd,data,len, 0,(struct sockaddr*)&kpeer, sizeof(kpeer));
	return 0;
}

int defense_rule_add(char * name,u32 pkts,u32 burst)
{
	struct msg_to_kernel message;
	arp_cfg_t * data;
	skfd = create_nl(ARP_DEFENSE_TYPE);
	if (skfd < 0)
	{
		return -1;
	}
	memset(&message, 0, sizeof(message));
	message.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(arp_cfg_t));                
	message.hdr.nlmsg_flags = MSG_ADD;
	message.hdr.nlmsg_type = ARP_DEFENSE_TYPE;                        /*设置自定义消息类型*/
	message.hdr.nlmsg_pid = getpid();                /*设置发送者的PID*/

	data = &message.data;

	//snprintf(data->name,strlen(name),name);
	snprintf(data->name,IFNAMSIZ,"%s",name);
	data->avg= pkts;
	data->burst = burst;
	
  /*发送一个请求*/
	send_to_kernel(&message,message.hdr.nlmsg_len);
	return 0;
}

int defense_rule_del(char *name)
{
	struct msg_to_kernel message;
	arp_cfg_t * data;

	skfd = create_nl(ARP_DEFENSE_TYPE);
	if (skfd < 0)
	{
		return -1;
	}
	memset(&message, 0, sizeof(message));
	message.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(arp_cfg_t));                
	message.hdr.nlmsg_flags = MSG_DEL;
	message.hdr.nlmsg_type = ARP_DEFENSE_TYPE;                     
	message.hdr.nlmsg_pid = getpid();

	data = &message.data;

	snprintf(data->name,IFNAMSIZ,"%s",name);
	data->avg= 0;
	data->burst = 0;
  /*发送一个请求*/
	send_to_kernel(&message,message.hdr.nlmsg_len);
	return 0;
}

int main(int argc,char * argv[])
{
	if (argc < 2)
	{
		printf("usage : [add]|[del]\n");
		return -1;
	}
	if (strcmp(argv[1],"del") == 0)
	{
		if (argc < 3)
		{
			printf("usage : [del] [rule name]\n");
			return -1;
		}
		defense_rule_del(argv[2]);
	}
	else if (strcmp(argv[1],"add") == 0)
	{
		if (argc < 5)
		{
			printf("usage : [add] [rule name] [pkts/sec] [burst]\n");
			return -1;
		}
		defense_rule_add(argv[2],atoi(argv[3]),atoi(argv[4]));
	}
	else
	{
		printf("usage : [add]|[del]\n");
		return -1;
	}
	
	if (skfd < 0)
	{
		return -1;
	}
	{
		struct sockaddr_nl kpeer;
		struct msg_to_kernel buf;
		int len;
		socklen_t fromlen;
		fromlen = sizeof(kpeer);
		len = recvfrom(skfd,&buf,sizeof(buf),0,(struct sockaddr *)&kpeer,&fromlen);
		if (len >= 0)
		{
			printf("kernel return : %x\n",buf.hdr.nlmsg_flags);
		}
		close(skfd);
	}
	return 0;
}