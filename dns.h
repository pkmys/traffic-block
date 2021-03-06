/* *
 * @module: dns.h
 * @author: Pawan Kumar
 * @email: jmppawanhit@gmail.com
 * @license: GPL
 * @domain: Linux Network Programming
 * @description: Demonstrating the simple firewall module 
 *               using netfilter hooks.
 * @copyright: Copyright (C) 2018
 */

#ifndef _DNS_H
#define _DNS_H

#include <linux/types.h>

#define DOMAIN_NAME_MAX_LEN 1024
#define DNS_PORT 53

#define H_DNS_QRY 0x00
#define H_DNS_RES 0x80
#define H_DNS_OPCODE_SQRY 0x00
#define H_DNS_OPCODE_IQRY 0x08
#define H_DNS_OPCODE_STAT 0x10
#define H_DNS_OPCODE_NOTY 0x20
#define H_DNS_OPCODE_UPDT 0x28
#define H_DNS_TYPE_AA 0x04
#define H_DNS_TYPE_TC 0x02
#define H_DNS_TYPE_RD 0x01

#define DNS_QR(dns) (((dns)->flag_h) & 0x80)     /*DNS type*/
#define DNS_OPCODE(dns) (((dns)->flag_h) & 0x78) /*DNS message type*/
#define DNS_AA(dns) (((dns)->flag_h) & 0x04)     /*DNS command answer*/
#define DNS_TC(dns) (((dns)->flag_h) & 0x02)     /*DNS is cut*/
#define DNS_RD(dns) (((dns)->flag_h) & 0x01)     /*DNS Resursive service*/
#define DNS_RA(dns) (((dns)->flag_l) & 0x80)     /*DNS flag recursion available bit*/
#define DNS_Z(dns) (((dns)->flag_l) & 0x70)      /*don't know about this bit*/
#define DNS_RCODE(dns) (((dns)->flag_l) & 0xF)   /*DNS flag return code*/

struct dnshdr
{
    u16 trans_id; /*transaction id*/
    u8 flag_h;    /*DNS flag high 8bit*/
    u8 flag_l;    /*DNS flag low  8bit*/
    u16 q_num;    /*DNS question number*/
    u16 r_num;    /*DNS answer number*/
    u16 ar_num;
    u16 er_num;
    unsigned char data[0];
};

void dns_get_domain_name(struct dnshdr *dnshr, unsigned char *domain);

#endif /* _DNS_H */