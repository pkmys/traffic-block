/* @module: traffic_filter_mod.h  
 * @author: Pawan Kumar
 * @email: jmppawanhit@gmail.com
 * @license: GPL
 * @domain: Linux Network Programming
 * @description: Demonstrating the simple firewall module 
 *               using netfilter hooks.
 * @copyright: Copyright (C) 2018
 */

#ifndef TRAFFIC_FILTER_MOD_H
#define TRAFFIC_FILTER_MOD_H

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
           __VA_ARGS__)

#define MAC_FMT  "%x:%x:%x:%x:%x:%x"
#define MAC(addr)   addr[0], addr[1], addr[2],\
                    addr[3], addr[4], addr[5]
#define NIP4_FMT "%u.%u.%u.%u"
#define NIP4(addr) ((addr >> 24) & 0xFF), ((addr >> 16) & 0xFF), \
                   ((addr >> 8) & 0xFF), ((addr >> 0) & 0xFF)

//filter support
#define MOD_SUPPORT_LOCAL_OUT
//#define MOD_SUPPORT_LOCAL_IN
//#define DBG_HEX_DUMP
//#define MOD_SUPPORT_TCP
#define MOD_SUPPORT_UDP
//#define MOD_SUPPORT_MAC

/**************************************************************
 *                                                            *
 *                         PROTOTYPES                         *
 *                                                            *
 **************************************************************/
unsigned int HOOK_FN(local_out_hook);
unsigned int HOOK_FN(local_in_hook);

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

/**************************************************************
 *                                                            *
 *                          TYPEDEFS                          *
 *                                                            *
 **************************************************************/
/**************************************************************
 *                                                            *
 *                          EXTERNS                           *
 *                                                            *
 **************************************************************/
extern void hex_dump_skb(struct sk_buff*);

#endif /* TRAFFIC_FILTER_MOD_H */