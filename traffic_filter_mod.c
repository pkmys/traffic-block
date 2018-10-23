/* @module: traffic_filter_mod.c  
 * @author: Pawan Kumar
 * @email: jmppawanhit@gmail.com
 * @license: GPL
 * @domain: Linux Network Programming
 * @description: Demonstrating the simple firewall module 
 *               using netfilter hooks.
 * @copyright: Copyright (C) 2018
 */

/**************************************************************
 *                                                            *
 *                         #includes                          *
 *                                                            *
 **************************************************************/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/errno.h>

#include "traffic_filter_mod.h"
#include "dns.h"

/**************************************************************
 *                                                            *
 *                          #MACROS                           *
 *                                                            *
 **************************************************************/
#define MOD_AUTHOR "Pawan Kumar <jmppawanhit@gmail.com>"
#define MOD_DESC "traffic filter kernel module"
#define MOD_SUPPORT "packet filter"
#define DEVICE_INTF_NAME "tfdev"
#define DEVICE_MAJOR_NUM 121

/**************************************************************
 *                                                            *
 *                           GLOBAL                           *
 *                                                            *
 **************************************************************/
uint8_t debug_level = 0xFF;
/* List node containing a filter rule */
struct rule_node
{
    local_rule_t rule;
    struct list_head list;
};

struct list_head In_lhead;  /* Head of inbound-rule list */
struct list_head Out_lhead; /* Head of outbound-rule list */

static int Device_open;   /* Opening counter of a device file */
static char *user_buffer; /* A buffer for receving data from a user space */

/**************************************************************
 *                                                            *
 *                          TYPEDEFS                          *
 *                                                            *
 **************************************************************/

/**************************************************************
 *                                                            *
 *                           MODINFO                          *
 *                                                            *
 **************************************************************/
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR(MOD_AUTHOR);
MODULE_DESCRIPTION(MOD_DESC);
MODULE_VERSION("0.1.0");
MODULE_SUPPORTED_DEVICE(MOD_SUPPORT);
MODULE_ALIAS("nf_firewall");

/**************************************************************
 *                                                            *
 *                         PROTOTYPES                         *
 *                                                            *
 **************************************************************/

/**************************************************************
 *                                                            *
 *                    COMMAND LINE ARGS.                      *
 *                                                            *
 **************************************************************/

/**************************************************************
 *                                                            *
 *                           FILTER                           *
 *                                                            *
 **************************************************************/
void hex_dump_skb(struct sk_buff *skb)
{
    do
    {
        int i;
        u8 *it = (u8 *)skb_mac_header(skb);
        printk("\n");
        printk("000000 ");
        for (i = 0; i < skb->len; i++)
        {
            printk("%02x ", (it[i]));
            if (15 == i % 16)
                printk("\n%06x: ", (i + 1));
        }
        printk("\n");
    } while (0);
}

unsigned int HOOK_FN(local_out_hook)
{

    struct iphdr *iphr = NULL;
    struct tcphdr *tcphr = NULL;
    struct udphdr *udphr = NULL;
    struct ethhdr *machr = NULL;
    __u32 saddr, daddr;
    __u16 sport, dport;
    unsigned char *payload = NULL; /* data as payload */

    if (!skb)
        return NF_ACCEPT;

    machr = eth_hdr(skb);
    iphr = ip_hdr(skb);
    saddr = ntohl(iphr->saddr);
    daddr = ntohl(iphr->daddr);

    if (iphr->protocol == IPPROTO_TCP)
    {
        tcphr = tcp_hdr(skb);
        sport = ntohs(tcphr->source);
        dport = ntohs(tcphr->dest);
        payload = (unsigned char *)((unsigned char *)tcphr + (tcphr->doff * 4));
    }
    else if (iphr->protocol == IPPROTO_UDP)
    {
        udphr = (struct udphdr *)skb_transport_header(skb);
        sport = ntohs(udphr->source);
        dport = ntohs(udphr->dest);
        payload = (unsigned char *)((unsigned char *)udphr + sizeof(*udphr));
    }
    return NF_ACCEPT;
}

unsigned int HOOK_FN(local_in_hook)
{

    struct iphdr *iphr = NULL;
    struct tcphdr *tcphr = NULL;
    struct udphdr *udphr = NULL;
    struct ethhdr *machr = NULL;
    __u32 saddr, daddr;
    __u16 sport, dport;
    unsigned char *payload = NULL; /* data as payload */

    if (!skb)
        return NF_ACCEPT;

    machr = eth_hdr(skb);
    iphr = ip_hdr(skb);
    saddr = ntohl(iphr->saddr);
    daddr = ntohl(iphr->daddr);
    if (iphr->protocol == IPPROTO_TCP)
    {
        tcphr = tcp_hdr(skb);
        sport = ntohs(tcphr->source);
        dport = ntohs(tcphr->dest);

        payload = (unsigned char *)((unsigned char *)tcphr + (tcphr->doff * 4));
    }
    else if (iphr->protocol == IPPROTO_UDP)
    {
        udphr = (struct udphdr *)skb_transport_header(skb);
        sport = ntohs(udphr->source);
        dport = ntohs(udphr->dest);
        payload = (unsigned char *)((unsigned char *)udphr + sizeof(*udphr));
    }
    return NF_ACCEPT;
}

/*
 * The function handles an open operation of a device file.
 */
static int tfdev_open(struct inode *inode, struct file *file)
{
    if (Device_open)
        return -EBUSY;

    /* Increase value to enforce a signal access policy */
    Device_open++;

    if (!try_module_get(THIS_MODULE))
    {
        DBG_ERR("Module is not available");
        return -ESRCH;
    }
    DBG_DEBUG("Opened " DEVICE_INTF_NAME);
    return 0;
}

/*
 * The function handles a release operation of a device file.
 */
static int tfdev_release(struct inode *inode, struct file *file)
{
    module_put(THIS_MODULE);
    Device_open--;
    DBG_DEBUG("Close " DEVICE_INTF_NAME);
    return 0;
}

/*
 * The function handles user-space view operation, which reads inbound and
 * outbound rules stored in the module. The function is called iteratively
 * until it returns 0.
 */
static ssize_t tfdev_read(struct file *file, char *buffer, size_t length, loff_t *offset)
{
    int error_count = 0;
    static struct list_head *inlp = &In_lhead;
    static struct list_head *outlp = &Out_lhead;
    struct rule_node *node;
    unsigned char *readptr;

    /* Read a rule if it is not the last one in the inbound list */
    if (inlp->next != &In_lhead)
    {
        node = list_entry(inlp->next, struct rule_node, list);
        readptr = (unsigned char *)&node->rule;
        inlp = inlp->next;
    }
    /* Read a rule if it is not the last one in the outbound list */
    else if (outlp->next != &Out_lhead)
    {
        node = list_entry(outlp->next, struct rule_node, list);
        readptr = (unsigned char *)&node->rule;
        outlp = outlp->next;
    }
    /* Reset reading pointers to heads of inbound and outbound lists */
    else
    {
        inlp = &In_lhead;
        outlp = &Out_lhead;
        return 0;
    }

    /* Write to a user-space buffer */
    error_count = copy_to_user(buffer, readptr, sizeof(local_rule_t));
    if (error_count == 0){
        DBG_DEBUG("Read OK");
    }else{
        DBG_ERR("Read Fail");
        return -EFAULT;
    }
    return sizeof(local_rule_t);
}

/*
 * The function adds a rule to either an inbound list or an outbound list.
 */
static void rule_add(local_rule_t *rule)
{
    struct rule_node *nodep;
    nodep = (struct rule_node *)kmalloc(sizeof(struct rule_node), GFP_KERNEL);
    if (nodep == NULL)
    {
        DBG_ERR("Cannot add a new rule due to insufficient memory");
        return;
    }
    nodep->rule = *rule;

    if (nodep->rule.in == 1)
    {
        list_add_tail(&nodep->list, &In_lhead);
        PRINT_INFO("NEW IN RULE:");
        PRINT_INFO("src ip: " NIP4_FMT "  src mask: " NIP4_FMT "  src port: %u"
                   "\ndest ip: " NIP4_FMT "  dest mask: " NIP4_FMT "  dest port: %u",
                   NIP4(nodep->rule.src_ip), NIP4(nodep->rule.src_mask), nodep->rule.src_port,
                   NIP4(nodep->rule.dst_ip), NIP4(nodep->rule.dst_mask), nodep->rule.dst_port);
    }
    else
    {
        list_add_tail(&nodep->list, &Out_lhead);
        PRINT_INFO("NEW OUT RULE:");
        PRINT_INFO("src ip: " NIP4_FMT "  src mask: " NIP4_FMT "  src port: %u"
                   "\ndest ip: " NIP4_FMT "  dest mask: " NIP4_FMT "  dest port: %u",
                   NIP4(nodep->rule.src_ip), NIP4(nodep->rule.src_mask), nodep->rule.src_port,
                   NIP4(nodep->rule.dst_ip), NIP4(nodep->rule.dst_mask), nodep->rule.dst_port);
    }
}

/*
 * The function deletes a rule from inbound and outbound lists.
 */
static void rule_del(local_rule_t *rule)
{
    struct rule_node *node;
    struct list_head *lheadp;
    struct list_head *lp;

    if (rule->in == 1)
        lheadp = &In_lhead;
    else
        lheadp = &Out_lhead;

    for (lp = lheadp; lp->next != lheadp; lp = lp->next)
    {
        node = list_entry(lp->next, struct rule_node, list);
        if (node->rule.in == rule->in &&
            node->rule.src_ip == rule->src_ip &&
            node->rule.src_mask == rule->src_mask &&
            node->rule.src_port == rule->src_port &&
            node->rule.dst_ip == rule->dst_ip &&
            node->rule.dst_mask == rule->dst_mask &&
            node->rule.dst_port == rule->dst_port &&
            node->rule.protocol == rule->protocol)
        {
            list_del(lp->next);
            kfree(node);
            if (rule->in == 1)
                PRINT_INFO("IN RULE DELETE:");
            else
                PRINT_INFO("OUT RULE DELETE:");
            PRINT_INFO("src ip: " NIP4_FMT "  src mask: " NIP4_FMT "  src port: %u"
                       "\ndest ip: " NIP4_FMT "  dest mask: " NIP4_FMT "  dest port: %u",
                       NIP4(rule->src_ip), NIP4(rule->src_mask), rule->src_port,
                       NIP4(rule->dst_ip), NIP4(rule->dst_mask), rule->dst_port);
            break;
        }
    }
}

/*
 * The function handles user-space write operation, which sends add and remove
 * instruction to the MiniFirewall module
 */
static ssize_t tfdev_write(struct file *file, const char *buffer, size_t length, loff_t *offset)
{
    tf_ctl_t *ctlp;
    int byte_write = 0;

    if (length < sizeof(tf_ctl_t))
    {
        DBG_WARN("Receives incomplete instruction");
        return byte_write;
    }

    /* Transfer user-space data to kernel-space buffer */
    copy_from_user(user_buffer, buffer, sizeof(tf_ctl_t));

    ctlp = (tf_ctl_t *)user_buffer;
    switch (ctlp->mode)
    {
    case MFW_ADD:
        rule_add(&ctlp->rule);
        break;
    case MFW_REMOVE:
        rule_del(&ctlp->rule);
        break;
    default:
        DBG_WARN("Received an unknown command");
    }

    return sizeof(tf_ctl_t);
}

static int __init nf_traffic_filter_init(void)
{
    int ret;
    /* Initialize static global variables */
    Device_open = 0;
    user_buffer = (char *)kzalloc(sizeof(tf_ctl_t), GFP_KERNEL);
    if (user_buffer == NULL)
    {
        DBG_ERR("MiniFirewall: Fails to start due to out of memory");
        return -ENOMEM;
    }
    INIT_LIST_HEAD(&In_lhead);
    INIT_LIST_HEAD(&Out_lhead);

    /* Register character device */
    ret = register_chrdev(DEVICE_MAJOR_NUM, DEVICE_INTF_NAME, &dev_fops);
    if (ret < 0)
    {
        DBG_ERR("Fails to start due to device register");
        return -ENODATA;
    }
    PRINT_INFO("Char device %s is registered with major number %d",
               DEVICE_INTF_NAME, DEVICE_MAJOR_NUM);
    PRINT_INFO("To communicate to the device, use: mknod %s c %d 0",
               DEVICE_INTF_NAME, DEVICE_MAJOR_NUM);

    /* Register netfilter inbound and outbound hooks */
    nf_register_hook(&local_out_filter);
    nf_register_hook(&local_in_filter);
    DBG_INFO("Module initialize OK");
    return 0;
}

static void __exit nf_traffic_filter_exit(void)
{
    struct rule_node *nodep;
    struct rule_node *ntmp;

    kfree(user_buffer);

    list_for_each_entry_safe(nodep, ntmp, &In_lhead, list)
    {
        list_del(&nodep->list);
        DBG_INFO("Deleted inbound rule %p", nodep);
        kfree(nodep);
    }
    list_for_each_entry_safe(nodep, ntmp, &Out_lhead, list)
    {
        list_del(&nodep->list);
        DBG_INFO("Deleted outbound rule %p", nodep);
        kfree(nodep);
    }

    unregister_chrdev(DEVICE_MAJOR_NUM, DEVICE_INTF_NAME);
    PRINT_INFO("Device %s is unregistered", DEVICE_INTF_NAME);
    nf_unregister_hook(&local_out_filter);
    nf_unregister_hook(&local_in_filter);
    DBG_INFO("Module uninitialize OK");
}

module_init(nf_traffic_filter_init);
module_exit(nf_traffic_filter_exit);