/* *
 * @module: util.c
 * @author: Pawan Kumar
 * @email: jmppawanhit@gmail.com
 * @license: GPL
 * @domain: Linux Network Programming
 * @description: Demonstrating the simple firewall module 
 *               using netfilter hooks.
 * @copyright: Copyright (C) 2018
 */

#include <linux/skbuff.h>
#include "util.h"

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