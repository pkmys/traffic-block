/* @module: traffic_filter_mod.h  
 * @author: Pawan Kumar
 * @email: jmppawanhit@gmail.com
 * @license: GPL
 * @domain: Linux Network Programming
 * @description: Demonstrating the simple firewall module 
 *               using netfilter hooks.
 * @copyright: Copyright (C) 2018
 */

#ifndef _TRAFFIC_FILTER_MOD_H
#define _TRAFFIC_FILTER_MOD_H

/**************************************************************
 *                                                            *
 *                         #includes                          *
 *                                                            *
 **************************************************************/
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

/**************************************************************
 *                                                            *
 *                          #MACROS                           *
 *                                                            *
 **************************************************************/

#define HOOK_FN(hook_name)                                               \
    hook_name(unsigned int hooknum, struct sk_buff *skb,                 \
              const struct net_device *in, const struct net_device *out, \
              int (*okfn)(struct sk_buff *))

//debug level mask
#define DEBUG_LEVEL_DEBUG 0x1F
#define DEBUG_LEVEL_INFO 0x0F
#define DEBUG_LEVEL_WARN 0x07
#define DEBUG_LEVEL_ERROR 0x03
#define DEBUG_LEVEL_CRITICAL 0x01

#define DBG_DEBUG(fmt, ...)                                     \
    if ((debug_level & DEBUG_LEVEL_DEBUG) == DEBUG_LEVEL_DEBUG) \
    printk(KERN_DEBUG "%s %d: " pr_fmt(fmt) "\n",               \
           __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define DBG_INFO(fmt, ...)                                    \
    if ((debug_level & DEBUG_LEVEL_INFO) == DEBUG_LEVEL_INFO) \
    printk(KERN_INFO "%s %d: " pr_fmt(fmt) "\n",              \
           __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define DBG_WARN(fmt, ...)                                    \
    if ((debug_level & DEBUG_LEVEL_WARN) == DEBUG_LEVEL_WARN) \
    printk(KERN_WARNING "%s %d: " pr_fmt(fmt) "\n",           \
           __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define DBG_ERR(fmt, ...)                                       \
    if ((debug_level & DEBUG_LEVEL_ERROR) == DEBUG_LEVEL_ERROR) \
    printk(KERN_ERR "%s %d: " pr_fmt(fmt) "\n",                 \
           __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define DBG_CRIT(fmt, ...)                                            \
    if ((debug_level & DEBUG_LEVEL_CRITICAL) == DEBUG_LEVEL_CRITICAL) \
    printk(KERN_CRIT "%s %d: " pr_fmt(fmt) "\n",                      \
           __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define PRINT_INFO(fmt, ...)                              \
    printk(KERN_INFO "traffic filter: " pr_fmt(fmt) "\n", \
           ##__VA_ARGS__)

#define MAC_FMT  "%x:%x:%x:%x:%x:%x"
#define MAC(addr)   addr[0], addr[1], addr[2],\
                    addr[3], addr[4], addr[5]
#define NIP4_FMT "%u.%u.%u.%u"
#define NIP4(addr) ((addr >> 24) & 0xFF), ((addr >> 16) & 0xFF), \
                   ((addr >> 8) & 0xFF), ((addr >> 0) & 0xFF)

#define EQUAL_NET_ADDR(ip1, ip2, mask) (((ip1 ^ ip2) & mask) == 0)

//filter support
#define MAX_KEY_LEN 64 
#define PRINT_RULE 44
#define PRINT_KEY 55
#define WRITE_RULE 66
#define WRITE_KEY 77

/**************************************************************
 *                                                            *
 *                          TYPEDEFS                          *
 *                                                            *
 **************************************************************/
typedef struct local_rule{
    uint8_t  in;
    uint16_t rule_no;
    uint32_t src_ip;
    uint32_t src_mask;
    uint32_t dst_ip;
    uint32_t dst_mask;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;    

} local_rule_t;

typedef struct tf_key{
    uint32_t key_id;
    unsigned char key[MAX_KEY_LEN]; 
} tf_key_t;

/* Mode of an instruction */
typedef enum ops_mode {
	MFW_NONE = 0,
	MFW_ADD_RULE = 1,
    MFW_ADD_KEY = 2,
	MFW_REMOVE_RULE = 3,
    MFW_REMOVE_KEY = 4,
	MFW_VIEW_RULE = 5,
    MFW_VIEW_KEYS =6
} ops_mode_t;

/* Control instruction */
typedef struct tf_ctl_rule {
	ops_mode_t mode;
	local_rule_t rule;
} tf_ctl_rule_t;

typedef struct tf_ctl_key {
    ops_mode_t mode;
    tf_key_t key;
} tf_ctl_key_t;

/**************************************************************
 *                                                            *
 *                         PROTOTYPES                         *
 *                                                            *
 **************************************************************/
unsigned int HOOK_FN(local_out_hook);
unsigned int HOOK_FN(local_in_hook);
void hex_dump_skb(struct sk_buff*);
static void rule_add(local_rule_t *rule);
static void rule_del(local_rule_t *rule);
static int tfdev_open(struct inode *inode, struct file *file);
static int tfdev_release(struct inode *inode, struct file *file);
static ssize_t tfdev_read(struct file *file, char *buffer, size_t length, loff_t *offset);
static ssize_t tfdev_write(struct file *file, const char *buffer, size_t length, loff_t *offset);
static long tfdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

/**************************************************************
 *                                                            *
 *                           GLOBAL                           *
 *                                                            *
 **************************************************************/
static struct nf_hook_ops local_out_filter = {
    .hook = (nf_hookfn *)local_out_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_FILTER,
};

static struct nf_hook_ops local_in_filter = {
    .hook = (nf_hookfn *)local_in_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FILTER,
};

struct file_operations dev_fops = {
    .owner = THIS_MODULE,
	.read = tfdev_read,
	.write = tfdev_write,
    .unlocked_ioctl = tfdev_ioctl,
	.open = tfdev_open,
	.release = tfdev_release
};

/**************************************************************
 *                                                            *
 *                          EXTERNS                           *
 *                                                            *
 **************************************************************/

#endif /* _TRAFFIC_FILTER_MOD_H */