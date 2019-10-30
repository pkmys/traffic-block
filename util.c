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

#include "util.h"
#include <linux/kernel.h>
#include <linux/errno.h>

void util_dump_hex(const __UINT8_TYPE__* const ptr, __UINT64_TYPE__ len)
{
    do
    {
        __INT32_TYPE__ i;
        printk("\n");
        printk("000000 ");
        for (i = 0; i < len; i++)
        {
            printk("%02x ", (ptr[i]));
            if (15 == i % 16)
                printk("\n%06x: ", (i + 1));
        }
        printk("\n");
    } while (0);
}

static int __id_allocator(__UINT64_TYPE__ *__key_array)
{
    __INT32_TYPE__ __id = 0;
    for (; __id < MAX_ENTRY; __id++)
    {
        if (__id < 64)
        {
            if (!(__key_array[0] & (1LU << __id)))
            {
                __key_array[0] |= (1UL << __id);
                return __id;
            }
        }
        else
        {
            if (!(__key_array[1] & (1LU << (__id - 64))))
            {
                __key_array[1] |= (1LU << (__id - 64));
                return __id;
            }
        }
    }
    return -EFAULT;
}

static void __id_deallocator(__INT32_TYPE__ __id, __UINT64_TYPE__ *__key_array)
{
    if (__id < 64)
        __key_array[0] &= ~(1LU << __id);
    else
        __key_array[1] &= ~(1LU << (__id - 64));
}

__INT32_TYPE__ inline util_id_allocate(__UINT64_TYPE__ *key_array)
{
    return __id_allocator(key_array);
}

void inline util_id_dallocate(__INT32_TYPE__ id, __UINT64_TYPE__ *key_array)
{
    return __id_deallocator(id, key_array);
}