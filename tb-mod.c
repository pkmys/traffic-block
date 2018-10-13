/* @module: tb-mod.c  
 * @author: Pawan Kumar
 * @email: jmppawanhit@gmail.com
 * @license: GPL
 * @domain: Linux Network Programming
 * @description: Demonstrating the simple  firewall  module.
 * @copyright: Copyright (C) 2018
 */


/******************************************
 *               includes                 *
 ******************************************/
#include <linux/module.h>       
#include <linux/kernel.h>       
#include <linux/init.h>         


/*******************************************
 *                modinfo                  *
 *******************************************/
#define MOD_AUTHOR "Pawan Kumar <jmppawanhit@gmail.com>"
#define MOD_DESC "traffic blocker kernel object"
#define MOD_SUPPORT "packet filter"

MODULE_LICENSE("Dual BSD/GPL");         
MODULE_AUTHOR(MOD_AUTHOR);             
MODULE_DESCRIPTION(MOD_DESC);       
MODULE_VERSION("0.1.0");                
MODULE_SUPPORTED_DEVICE(MOD_SUPPORT);

/*******************************************
 *                  global                 *
 *******************************************/
 
/********************************************
 *                prototypes                *
 ********************************************/
 
 /*******************************************
  *       command line variable setting     *
  *******************************************/
 
 /*******************************************
  *                  start                  *
  *******************************************/
 module_init();
 module_exit();
