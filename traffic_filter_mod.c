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
#include <linux/version.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/string.h>

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
#define CLASS_NAME "tfdev"

#define RD_GEN_TABLE _IOW(DEVICE_MAJOR_NUM, 1, uint32_t *)
#define RD_KEY_TABLE _IOW(DEVICE_MAJOR_NUM, 2, uint32_t *)
#define WR_GEN_TABLE _IOW(DEVICE_MAJOR_NUM, 3, uint32_t *)
#define WR_KEY_TABLE _IOW(DEVICE_MAJOR_NUM, 4, uint32_t *)

/**************************************************************
 *                                                            *
 *                           GLOBAL                           *
 *                                                            *
 **************************************************************/
uint8_t debug_level = 0xFF;

static struct list_head In_lhead;  /* Head of inbound-rule list */
static struct list_head Out_lhead; /* Head of outbound-rule list */
static struct list_head key_lhead;

static int Device_open; /* Opening counter of a device file */

static struct class *tfdev_class = NULL;   // The device-driver class struct pointer
static struct device *tfdev_device = NULL; // The device-driver device struct pointer

static int PRINT_SWITCH;
static int WRITE_SWITCH;

/* List node containing a filter rule */
struct rule_node
{
    local_rule_t rule;
    struct list_head list;
};

struct key_node
{
    tf_key_t key;
    struct list_head list;
};

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

static unsigned int HOOK_FN(local_out_hook)
{

    struct iphdr *iphr = NULL;
    struct tcphdr *tcphr = NULL;
    struct udphdr *udphr = NULL;
    struct ethhdr *machr = NULL;
    __u32 saddr, daddr;
    __u16 sport, dport;
    unsigned char *payload = NULL; /* data as payload */
    unsigned char dns_domain[DOMAIN_NAME_MAX_LEN];
    char *ret;
    struct key_node *node = NULL;
    struct list_head *lheadp = &key_lhead;
    struct list_head *lp = NULL;

    if (!skb || lheadp->next == lheadp)
        return NF_ACCEPT;

    machr = eth_hdr(skb);
    iphr = ip_hdr(skb);

    if (iphr)
    {
        saddr = ntohl(iphr->saddr);
        daddr = ntohl(iphr->daddr);
        switch (iphr->protocol)
        {
        case IPPROTO_TCP:
            tcphr = tcp_hdr(skb);
            sport = ntohs(tcphr->source);
            dport = ntohs(tcphr->dest);
            payload = (unsigned char *)((unsigned char *)tcphr + (tcphr->doff * 4));
            break;

        case IPPROTO_UDP:
            udphr = (struct udphdr *)skb_transport_header(skb);
            sport = ntohs(udphr->source);
            dport = ntohs(udphr->dest);
            payload = (unsigned char *)((unsigned char *)udphr + sizeof(*udphr));

            if (dport == DNS_PORT)
            {
                dns_get_domain_name((struct dnshdr *)payload, dns_domain);
                for (lp = lheadp; lp->next != lheadp; lp = lp->next)
                {
                    node = list_entry(lp->next, struct key_node, list);
                    ret = strstr(dns_domain, node->key.key);
                    if (ret != NULL)
                    {
                        DBG_DEBUG("[BLOCKED] DNS: %s", dns_domain);
                        return NF_DROP;
                    }
                }
            }
            break;

        default:
            break;
        }
    }
    return NF_ACCEPT;
}

static unsigned int HOOK_FN(local_in_hook)
{

    struct iphdr *iphr = NULL;
    struct tcphdr *tcphr = NULL;
    struct udphdr *udphr = NULL;
    struct ethhdr *machr = NULL;
    __u32 saddr, daddr;
    __u16 sport, dport;
    unsigned char *payload = NULL; /* data as payload */
    struct list_head *lheadp = &key_lhead;

    if (!skb || lheadp->next == lheadp)
        return NF_ACCEPT;

    machr = eth_hdr(skb);
    iphr = ip_hdr(skb);

    if (iphr)
    {
        saddr = ntohl(iphr->saddr);
        daddr = ntohl(iphr->daddr);
        switch (iphr->protocol)
        {
        case IPPROTO_TCP:
            tcphr = tcp_hdr(skb);
            sport = ntohs(tcphr->source);
            dport = ntohs(tcphr->dest);

            payload = (unsigned char *)((unsigned char *)tcphr + (tcphr->doff * 4));
            break;
        case IPPROTO_UDP:
            udphr = (struct udphdr *)skb_transport_header(skb);
            sport = ntohs(udphr->source);
            dport = ntohs(udphr->dest);
            payload = (unsigned char *)((unsigned char *)udphr + sizeof(*udphr));
            break;

        default:
            break;
        }
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
    static struct list_head *keylp = &key_lhead;
    struct rule_node *node;
    struct key_node *knode;
    unsigned char *readptr;

    if (PRINT_SWITCH == PRINT_RULE)
    {

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
        if (error_count == 0)
        {
            DBG_DEBUG("Read OK");
        }
        else
        {
            DBG_ERR("Read Fail");
            return -EFAULT;
        }
        return sizeof(local_rule_t);
    }
    else if (PRINT_SWITCH == PRINT_KEY)
    {
        if (keylp->next != &key_lhead)
        {
            knode = list_entry(keylp->next, struct key_node, list);
            readptr = (unsigned char *)&knode->key;
            keylp = keylp->next;
        }
        else
        {
            keylp = &key_lhead;
            return 0;
        }

        /* Write to a user-space buffer */
        error_count = copy_to_user(buffer, readptr, sizeof(tf_key_t));
        if (error_count == 0)
        {
            DBG_DEBUG("Read OK");
        }
        else
        {
            DBG_ERR("Read Fail");
            return -EFAULT;
        }
        return sizeof(tf_key_t);
    }
    return 0;
}

/*
 * The function adds a rule to either an inbound list or an outbound list.
 */
static void rule_add(local_rule_t *rule)
{
    struct rule_node *nodep;
    static uid16_t rule_no = 1;
    nodep = (struct rule_node *)kmalloc(sizeof(struct rule_node), GFP_KERNEL);
    if (nodep == NULL)
    {
        DBG_ERR("Cannot add a new rule due to insufficient memory");
        return;
    }
    rule->rule_no = rule_no;
    nodep->rule = *rule;

    if (nodep->rule.in == 1)
    {
        list_add_tail(&nodep->list, &In_lhead);
        PRINT_INFO("NEW IN RULE:");
        PRINT_INFO("src ip: " NIP4_FMT "  src mask: " NIP4_FMT "  src port: %u"
                   " dest ip: " NIP4_FMT "  dest mask: " NIP4_FMT "  dest port: %u",
                   NIP4(nodep->rule.src_ip), NIP4(nodep->rule.src_mask), nodep->rule.src_port,
                   NIP4(nodep->rule.dst_ip), NIP4(nodep->rule.dst_mask), nodep->rule.dst_port);
    }
    else
    {
        list_add_tail(&nodep->list, &Out_lhead);
        PRINT_INFO("NEW OUT RULE:");
        PRINT_INFO("src ip: " NIP4_FMT "  src mask: " NIP4_FMT "  src port: %u"
                   " dest ip: " NIP4_FMT "  dest mask: " NIP4_FMT "  dest port: %u",
                   NIP4(nodep->rule.src_ip), NIP4(nodep->rule.src_mask), nodep->rule.src_port,
                   NIP4(nodep->rule.dst_ip), NIP4(nodep->rule.dst_mask), nodep->rule.dst_port);
    }
    rule_no++;
}

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
        if (node->rule.rule_no == rule->rule_no)
        {
            list_del(lp->next);
            kfree(node);
            if (rule->in == 1)
                PRINT_INFO("IN RULE DELETE:");
            else
                PRINT_INFO("OUT RULE DELETE:");
            PRINT_INFO("src ip: " NIP4_FMT "  src mask: " NIP4_FMT "  src port: %u"
                       " dest ip: " NIP4_FMT "  dest mask: " NIP4_FMT "  dest port: %u",
                       NIP4(rule->src_ip), NIP4(rule->src_mask), rule->src_port,
                       NIP4(rule->dst_ip), NIP4(rule->dst_mask), rule->dst_port);
            break;
        }
    }
}

/*
 * The function deletes a rule from inbound and outbound lists.
 */
static void key_del(tf_key_t *key)
{
    struct key_node *node;
    struct list_head *lheadp;
    struct list_head *lp;

    lheadp = &key_lhead;

    for (lp = lheadp; lp->next != lheadp; lp = lp->next)
    {
        node = list_entry(lp->next, struct key_node, list);
        if (node->key.key_id == key->key_id)
        {
            list_del(lp->next);
            PRINT_INFO("Deleted key_id:%d  key:%s", key->key_id, node->key.key);
            kfree(node);
            break;
        }
    }
}

static void key_add(tf_key_t *key)
{
    struct key_node *nodep;
    static uint32_t key_id = 1;
    nodep = (struct key_node *)kmalloc(sizeof(struct key_node), GFP_KERNEL);
    if (nodep == NULL)
    {
        DBG_ERR("Cannot add a new key due to insufficient memory");
        return;
    }
    key->key_id = key_id;
    nodep->key = *key;

    list_add_tail(&nodep->list, &key_lhead);
    PRINT_INFO("Added key_id:%d key:%s", key_id, key->key);
    key_id++;
}

/*
 * The function handles user-space write operation, which sends add and remove
 * instruction to the MiniFirewall module
 */
static ssize_t tfdev_write(struct file *file, const char *buffer, size_t length, loff_t *offset)
{
    tf_ctl_rule_t *ctlp;
    tf_ctl_key_t *ctlk;
    char *user_buffer = NULL;
    int byte_write = 0;

    if (WRITE_SWITCH == WRITE_RULE)
    {

        if (length < sizeof(tf_ctl_rule_t))
        {
            DBG_WARN("Receives incomplete instruction");
            return byte_write;
        }

        user_buffer = (char *)kmalloc(length, GFP_KERNEL);
        if (user_buffer == NULL)
        {
            DBG_ERR("Alloc error for user_buffer insufficient memory");
            return -ENOMEM;
        }

        /* Transfer user-space data to kernel-space buffer */
        copy_from_user(user_buffer, buffer, sizeof(tf_ctl_rule_t));

        ctlp = (tf_ctl_rule_t *)user_buffer;
        switch (ctlp->mode)
        {
        case MFW_ADD_RULE:
            rule_add(&ctlp->rule);
            break;
        case MFW_REMOVE_RULE:
            rule_del(&ctlp->rule);
            break;
        default:
            DBG_WARN("Received an unknown command");
        }
	kfree(user_buffer);
        return sizeof(tf_ctl_rule_t);
    }
    else if (WRITE_SWITCH == WRITE_KEY)
    {
        if (length < sizeof(tf_ctl_key_t))
        {
            DBG_WARN("Receives incomplete instruction");
            return byte_write;
        }

        user_buffer = (char *)kmalloc(length, GFP_KERNEL);
        if (user_buffer == NULL)
        {
            DBG_ERR("Alloc error for user_buffer insufficient memory");
            return -ENOMEM;
        }

        /* Transfer user-space data to kernel-space buffer */
        copy_from_user(user_buffer, buffer, sizeof(tf_ctl_key_t));

        ctlk = (tf_ctl_key_t *)user_buffer;
        switch (ctlk->mode)
        {
        case MFW_ADD_KEY:
            key_add(&ctlk->key);
            break;
        case MFW_REMOVE_KEY:
            key_del(&ctlk->key);
            break;
        default:
            DBG_WARN("Received an unknown command");
        }
	kfree(user_buffer);
        return sizeof(tf_ctl_key_t);
    }

    return -EFAULT;
}

static long tfdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd)
    {
    case RD_GEN_TABLE:
        PRINT_SWITCH = PRINT_RULE;
        return 0;
    case RD_KEY_TABLE:
        PRINT_SWITCH = PRINT_KEY;
        return 0;
    case WR_GEN_TABLE:
        WRITE_SWITCH = WRITE_RULE;
        return 0;
    case WR_KEY_TABLE:
        WRITE_SWITCH = WRITE_KEY;
        return 0;
    default:
        return -1;
    }
}

static int __init nf_traffic_filter_init(void)
{
    int ret;
    /* Initialize static global variables */
    Device_open = 0;

    /* Register character device */
    ret = register_chrdev(DEVICE_MAJOR_NUM, DEVICE_INTF_NAME, &dev_fops);
    if (ret < 0)
    {
        DBG_ERR("Fails to start due to device register");
        return -ENODATA;
    }

    tfdev_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(tfdev_class))
    { // Check for error and clean up if there is
        unregister_chrdev(DEVICE_MAJOR_NUM, DEVICE_INTF_NAME);
        DBG_ERR("failed to register device class");
        return PTR_ERR(tfdev_class); // Correct way to return an error on a pointer
    }

    DBG_DEBUG("device class registered correctly");

    tfdev_device = device_create(tfdev_class, NULL, MKDEV(DEVICE_MAJOR_NUM, 0), NULL, DEVICE_INTF_NAME);
    if (IS_ERR(tfdev_device))
    { // Clean up if there is an error
        class_destroy(tfdev_class);
        unregister_chrdev(DEVICE_MAJOR_NUM, DEVICE_INTF_NAME);
        DBG_ERR("failed to create device");
        return PTR_ERR(tfdev_device);
    }

    /* Register netfilter inbound and outbound hooks */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    nf_register_net_hook(&init_net, &local_in_filter);
    nf_register_net_hook(&init_net, &local_out_filter);
#else
    nf_register_hook(&local_in_filter);
    nf_register_hook(&local_out_filter);
#endif
    INIT_LIST_HEAD(&In_lhead);
    INIT_LIST_HEAD(&Out_lhead);
    INIT_LIST_HEAD(&key_lhead);
    PRINT_INFO("Module initialize OK");
    return 0;
}

static void __exit nf_traffic_filter_exit(void)
{
    struct rule_node *nodep;
    struct rule_node *ntmp;
    struct key_node *knodep;
    struct key_node *ktmp;

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
    list_for_each_entry_safe(knodep, ktmp, &key_lhead, list)
    {
        list_del(&knodep->list);
        DBG_INFO("Deleted key %s", knodep->key.key);
        kfree(knodep);
    }

    device_destroy(tfdev_class, MKDEV(DEVICE_MAJOR_NUM, 0));
    class_unregister(tfdev_class);
    class_destroy(tfdev_class);
    unregister_chrdev(DEVICE_MAJOR_NUM, DEVICE_INTF_NAME);
    DBG_INFO("Device %s is unregistered", DEVICE_INTF_NAME);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    nf_unregister_net_hook(&init_net, &local_out_filter);
    nf_unregister_net_hook(&init_net, &local_in_filter);
#else
    nf_unregister_hook(&local_out_filter);
    nf_unregister_hook(&local_in_filter);
#endif
    PRINT_INFO("Module uninitialize OK");
}

module_init(nf_traffic_filter_init);
module_exit(nf_traffic_filter_exit);
