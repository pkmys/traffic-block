/* *
 * @module: dns.c
 * @author: Pawan Kumar
 * @email: jmppawanhit@gmail.com
 * @license: GPL
 * @domain: Linux Network Programming
 * @description: Demonstrating the simple firewall module 
 *               using netfilter hooks.
 * @copyright: Copyright (C) 2018
 */

#include <linux/string.h>
#include "dns.h"

static inline unsigned char *dns_get_payload(struct dnshdr *dnshr);

static inline unsigned char *dns_get_payload(struct dnshdr *dnshr)
{
    return (unsigned char *)dnshr + sizeof(struct dnshdr);
}

void dns_get_domain_name(struct dnshdr *dnshr, unsigned char *domain)
{
    unsigned char *dns_pload = dns_get_payload(dnshr);
    u8 next = dns_pload[0];
    u16 i, host_len = 0;

    dns_pload++;
    memset(domain, 0, DOMAIN_NAME_MAX_LEN);
    while (next != 0 && host_len < DOMAIN_NAME_MAX_LEN - 1)
    {
        for (i = 0; i < next; i++, host_len++)
        {
            domain[host_len] = dns_pload[host_len];
        }
        next = dns_pload[host_len];
        domain[host_len] = '.';
        host_len++;
    }
}