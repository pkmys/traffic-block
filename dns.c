#include "dns.h"
/*
void dns_get_domain_name(struct dnshdr *dnshr, unsigned char *domain)
{
    unsigned char *dns_pload = dns_get_payload(dnshr);
    u8 next = dns_pload[0];
    u16 i, host_len = 0;

    dns_pload++;
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
}*/