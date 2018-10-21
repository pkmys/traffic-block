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

/**************************************************************
 *                                                            *
 *                           GLOBAL                           *
 *                                                            *
 **************************************************************/
uint8_t debug_level = 0xFF;

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
 *                           START                            *
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

static void print_dns(u8 *payload)
{

    u8 next = payload[12];
    u16 host_len = 0, i;
    payload += 13;

    printk("domain: ");
    while (next != 0 && host_len < 1022)
    {
        for (i = 0; i < next; i++, host_len++)
        {
            printk("%c", payload[host_len]);
        }
        next = payload[host_len];
        host_len++;
        printk(".");
    }
    printk("\n");
}

unsigned int HOOK_FN(local_out_hook)
{

    struct iphdr *iphr = NULL;
    struct tcphdr *tcphr = NULL;
    struct udphdr *udphr = NULL;
    struct ethhdr *machr = NULL;
    __u32 saddr, daddr;
    __u16 sport, dport;
    unsigned char *data = NULL; /* data as payload */
    unsigned char *tail;        /* data end pointer */
    unsigned char *it;          /* data iterator */

    if (!skb)
        return NF_ACCEPT;

#ifdef MOD_SUPPORT_MAC
    machr = eth_hdr(skb);
    DBG_DEBUG("srce mac " MAC_FMT " dest mac " MAC_FMT, MAC(machr->h_source), MAC(machr->h_dest));
#endif

    iphr = ip_hdr(skb);
    saddr = ntohl(iphr->saddr);
    daddr = ntohl(iphr->daddr);
#ifdef MOD_SUPPORT_TCP
    if (iphr->protocol == IPPROTO_TCP)
    {
        tcphr = tcp_hdr(skb);
        sport = ntohs(tcphr->source);
        dport = ntohs(tcphr->dest);

        data = (unsigned char *)((unsigned char *)tcphr + (tcphr->doff * 4));

        DBG_DEBUG("TCP srce Port: %u dest Port: %u", sport, dport);
        tail = skb_tail_pointer(skb);
        DBG_DEBUG("DATA: ");
        for (it = data; it != tail; ++it)
        {
            char c = *(char *)it;

            if (c == '\0')
                break;

            printk("%c", c);
        }
        printk("\n\n");
    }
    else
#endif
#ifdef MOD_SUPPORT_UDP
    if (iphr->protocol == IPPROTO_UDP)
    {
        udphr = (struct udphdr *)skb_transport_header(skb);
        sport = ntohs(udphr->source);
        dport = ntohs(udphr->dest);

        if (dport == 53)
        {
            data = (unsigned char *)((unsigned char *)udphr + sizeof(*udphr));

            DBG_DEBUG("UDP srce Port: %u dest Port: %u", sport, dport);
            print_dns(data);
        }
    }
#endif
#ifdef DBG_HEX_DUMP
    hex_dump_skb(skb);
#endif
#ifdef MOD_IP_TRACE
    DBG_DEBUG("srce IP: " NIP4_FMT " dest IP: " NIP4_FMT, NIP4(saddr), NIP4(daddr));
#endif

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
    unsigned char *data = NULL; /* data as payload */

    if (!skb)
        return NF_ACCEPT;

#ifdef MOD_SUPPORT_MAC
    machr = eth_hdr(skb);
    DBG_DEBUG("srce mac " MAC_FMT " dest mac " MAC_FMT, MAC(machr->h_source), MAC(machr->h_dest));
#endif

    iphr = ip_hdr(skb);
    saddr = ntohl(iphr->saddr);
    daddr = ntohl(iphr->daddr);
#ifdef MOD_SUPPORT_TCP
    if (iphr->protocol == IPPROTO_TCP)
    {
        tcphr = tcp_hdr(skb);
        sport = ntohs(tcphr->source);
        dport = ntohs(tcphr->dest);

        data = (unsigned char *)((unsigned char *)tcphr + (tcphr->doff * 4));

        DBG_DEBUG("TCP srce Port: %u dest Port: %u", sport, dport);
        tail = skb_tail_pointer(skb);
        DBG_DEBUG("DATA: ");
        for (it = data; it != tail; ++it)
        {
            char c = *(char *)it;

            if (c == '\0')
                break;

            printk("%c", c);
        }
        printk("\n\n");
    }
    else
#endif
#ifdef MOD_SUPPORT_UDP
        if (iphr->protocol == IPPROTO_UDP)
    {
        udphr = (struct udphdr *)skb_transport_header(skb);
        sport = ntohs(udphr->source);
        dport = ntohs(udphr->dest);

        if (dport == 53)
        {
            data = (unsigned char *)((unsigned char *)udphr + sizeof(*udphr));
            DBG_DEBUG("UDP srce Port: %u dest Port: %u", sport, dport);
            print_dns(data);
        }
    }
#endif
#ifdef DBG_HEX_DUMP
    hex_dump_skb(skb);
#endif
#ifdef MOD_IP_TRACE
    DBG_DEBUG("srce IP: " NIP4_FMT " dest IP: " NIP4_FMT, NIP4(saddr), NIP4(daddr));
#endif
    return NF_ACCEPT;
}

static int __init nf_traffic_filter_init(void)
{
#ifdef MOD_SUPPORT_LOCAL_OUT
    nf_register_hook(&local_out_filter);
#endif
#ifdef MOD_SUPPORT_LOCAL_IN
    nf_register_hook(&local_in_filter);
#endif
    return 0;
}

static void __exit nf_traffic_filter_exit(void)
{
#ifdef MOD_SUPPORT_LOCAL_OUT
    nf_unregister_hook(&local_out_filter);
#endif
#ifdef MOD_SUPPORT_LOCAL_IN
    nf_unregister_hook(&local_in_filter);
#endif
}

module_init(nf_traffic_filter_init);
module_exit(nf_traffic_filter_exit);
