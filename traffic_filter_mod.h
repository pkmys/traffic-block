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
#define    NF_IP_LOCAL_OUT		3

#define HOOK_FN(hook_name)                                               \
    hook_name(unsigned int hooknum, struct sk_buff **skb,                \
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
/**************************************************************
 *                                                            *
 *                         PROTOTYPES                         *
 *                                                            *
 **************************************************************/
unsigned int HOOK_FN(local_out_hook);

/**************************************************************
 *                                                            *
 *                           GLOBAL                           *
 *                                                            *
 **************************************************************/
/*
/*        Protocol families .pf 
                (MACRO) 
	PF_UNSPEC	0	// Unspecified.  
	PF_INET		2	// IP protocol family.  
	PF_INET6	10	// IP version 6.

            hook type  .hooknum
                (MACRO)
    NF_IP_PRE_ROUTING	0 //After promisc drops, checksum checks.
    NF_IP_LOCAL_IN		1 //If the packet is destined for this box.
    NF_IP_FORWARD		2 //If the packet is destined for another interface.
    NF_IP_LOCAL_OUT		3 //Packets coming from a local process.
    NF_IP_POST_ROUTING	4 //Packets about to hit the wire.

      hook chain priority order  .priority
                (enum)

    NF_IP_PRI_FIRST = INT_MIN,
	NF_IP_PRI_CONNTRACK_DEFRAG = -400,
	NF_IP_PRI_RAW = -300,
	NF_IP_PRI_SELINUX_FIRST = -225,
	NF_IP_PRI_CONNTRACK = -200,
	NF_IP_PRI_MANGLE = -150,
	NF_IP_PRI_NAT_DST = -100,
	NF_IP_PRI_FILTER = 0,       
	NF_IP_PRI_SECURITY = 50,
	NF_IP_PRI_NAT_SRC = 100,
	NF_IP_PRI_SELINUX_LAST = 225,
	NF_IP_PRI_CONNTRACK_HELPER = 300,
	NF_IP_PRI_CONNTRACK_CONFIRM = INT_MAX,
	NF_IP_PRI_LAST = INT_MAX,
*/
static struct nf_hook_ops local_out_filter = {
    .hook = local_out_hook,
    .pf = PF_INET,
    .hooknum = NF_IP_LOCAL_OUT,
    .priority = NF_IP_PRI_FILTER,
};

/**************************************************************
 *                                                            *
 *                          TYPEDEFS                          *
 *                                                            *
 **************************************************************/

/**************************************************************
 *                                                            *
 *                           START                            *
 *                                                            *
 **************************************************************/

#endif /* TRAFFIC_FILTER_MOD_H */