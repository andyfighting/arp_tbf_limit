#ifndef __HASH_TBL__
#define __HASH_TBL__

#include <linux/list.h>
#include <linux/spinlock_types.h>
#include <linux/slab.h>
#include "arp_hash.h"

struct hash_head
{
	spinlock_t spin_lock;
	unsigned long spin_irq_flags;
	unsigned int key;
	int        list_count;

	struct list_head head;
};

struct hash_node
{
	unsigned int key;
	struct list_head   node;
};

struct hash_tbl
{
	unsigned int hash_size;
	struct hash_head * table;
};

typedef void * (*hash_cmp)(struct hash_node *,void *);
typedef int (*hash_proc)(struct hash_node *,void *);

/**
 * hash_node_entry - get the struct for this entry
 * @ptr:	the &struct hash_node pointer.
 * @type:	the type of the struct this is embedded in.
 * @member: the name of the hash_node within the struct.
 */

#define hash_node_entry(ptr,type,member) \
	container_of(ptr,type,member)

/**
 * list_head_to_hash_node - get hash_node from list_head
 * @list_head: the &struct list_head pointer.
 */

#define list_head_to_hash_node(list_head) \
	container_of(list_head,struct hash_node,node)


static inline struct hash_head * get_hash_head(struct hash_tbl * tbl,unsigned int hash_key)
{
	struct hash_head * head;
	hash_key %= tbl->hash_size;
	head = &tbl->table[hash_key];
	spin_lock_irqsave(&head->spin_lock,head->spin_irq_flags);
	return head;
}

static inline void free_hash_head(struct hash_head * hash_head)
{
	spin_unlock_irqrestore(&hash_head->spin_lock,hash_head->spin_irq_flags);
}


static inline int hash_for_each_proc(struct hash_tbl * tbl,hash_proc proc,void * data)
{
	struct hash_head * head;
	struct hash_node * pos;
	struct hash_node * next;
	unsigned int hash_key;
	int ret = 0;

	for (hash_key = 0;hash_key < tbl->hash_size;hash_key++)
	{
		head = get_hash_head(tbl,hash_key);
		
		list_for_each_entry_safe(pos,next,&head->head,node)
		{
			ret = proc(pos,data);
			if (ret)
			{

			}
		}
		free_hash_head(head);
	}
	return ret;

}

static inline void * find_from_hash_tbl(struct hash_tbl * table,
									 unsigned int hash_key,
									 hash_cmp cmp,
									 void * data)
{
	struct hash_head * head;
	struct hash_node * pos;
	struct hash_node * next;
	void * ret = NULL;

	head = get_hash_head(table,hash_key);
	
	list_for_each_entry_safe(pos,next,&head->head,node)
	{
		ret = cmp(pos,data);
	}
	free_hash_head(head);
	return ret;
}

static inline int add_to_hash_tbl(struct hash_tbl * table,struct hash_node * node,unsigned int hash_key)
{
	struct hash_head * head;

	hash_key %= table->hash_size;

	head = get_hash_head(table,hash_key);
	
	node->key = hash_key;
	
	list_add(&node->node,&head->head);
	head->list_count++;

	free_hash_head(head);
	return 0;
}

static inline void __del_from_hash_tbl(struct hash_node * node)
{
	list_del(&node->node);
}

static inline int del_from_hash_tbl(struct hash_tbl * table,struct hash_node * node)
{
	struct hash_head * head;
	head = get_hash_head(table,node->key);

	__del_from_hash_tbl(node);
	head->list_count--;

	free_hash_head(head);
	return 0;
}


static inline int init_hash_head(struct hash_head * head,unsigned int key)
{
	head->spin_lock = SPIN_LOCK_UNLOCKED;
	head->key = key;
	INIT_LIST_HEAD(&head->head);
	return 0;
}

static inline int init_hash_tbl(struct hash_tbl * table,unsigned int hash_size)
{
	struct hash_head * hash_head_list;
	unsigned int index;

	hash_head_list = (struct hash_head *)kmalloc(sizeof(struct hash_head)*hash_size,GFP_ATOMIC);
	if (hash_head_list == NULL)
	{
		return -1;
	}
	table->table = hash_head_list;
	table->hash_size = hash_size;
	for (index = 0;index < hash_size;index++)
	{
		init_hash_head(&hash_head_list[index],index);
	}
	return 0;
}

static inline int free_hash_tbl(struct hash_tbl * table)
{
	unsigned int hash_size;

	hash_size      = table->hash_size;
	kfree(table->table);
	return 0;
}

static inline int destroy_hash_tbl(struct hash_tbl * tbl,hash_proc del_node,void * data)
{
	hash_for_each_proc(tbl,del_node,data);
	return free_hash_tbl(tbl);
}

#endif
