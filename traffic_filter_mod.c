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

#include "traffic_filter_mod.h"   

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
uint8_t debug_level = DEBUG_LEVEL_DEBUG;
 
/**************************************************************
 *                                                            *
 *                           START                            *
 *                                                            *
 **************************************************************/
unsigned int HOOK_FN(local_out_hook){
    DBG_INFO("packet dropped");

    return NF_DROP;
}

static int __init nf_traffic_filter_init(void)
{
    nf_register_hook(&local_out_filter);
    return 0;
}

static void __exit nf_traffic_filter_exit(void)
{
    nf_unregister_hook(&local_out_filter);
}

module_init(nf_traffic_filter_init);
module_exit(nf_traffic_filter_exit);
