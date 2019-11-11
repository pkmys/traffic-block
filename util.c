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
#include <linux/string.h>

void util_dump_hex(const __UINT8_TYPE__* const ptr, __UINT64_TYPE__ len)
{
    __UINT32_TYPE__ i = 0;
    __UINT32_TYPE__ k = 0;
    __UINT32_TYPE__ j = 0;
    char buffer[128] = {0};
    printk("DUMP %p, %lu:", ptr, len);
    printk("\n");
    j = snprintf(buffer, 18, "      0x000000:  ");
    for (i = 0; i < len; i++)
    {
        j += snprintf(buffer+j , 3, "%02x", ptr[i]);
        if (i & 0x01)
            j += snprintf(buffer+j , 2, " ");
        if (15 == i % 16)
        {
            j += snprintf(buffer+j , 2, " ");
            for (k = (i - 16); k < i; k++)
            {
                if (ptr[k] <= 0x7F)
                    j += snprintf(buffer+j , 2, "%c", ptr[k]);
                else
                    j += snprintf(buffer+j , 2, ".");
            }
            printk("%s", buffer);
            memset(buffer, 0, 128);
            j = 0;
            j += snprintf(buffer+j , 18, "      0x%06x:  ", (i + 1));
        }
    }
    printk("\n");
}

static int id_allocator(__UINT64_TYPE__ *key_array)
{
    __INT32_TYPE__ id = 0;
    for (; id < MAX_ENTRY; id++)
    {
        if (id < 64)
        {
            if (!(key_array[0] & (1LU << id)))
            {
                key_array[0] |= (1UL << id);
                return id;
            }
        }
        else
        {
            if (!(key_array[1] & (1LU << (id - 64))))
            {
                key_array[1] |= (1LU << (id - 64));
                return id;
            }
        }
    }
    return -EFAULT;
}

static void id_deallocator(__INT32_TYPE__ id, __UINT64_TYPE__ *key_array)
{
    if (id < 64)
        key_array[0] &= ~(1LU << id);
    else
        key_array[1] &= ~(1LU << (id - 64));
}

__INT32_TYPE__ util_id_allocate(__UINT64_TYPE__ *key_array)
{
    return id_allocator(key_array);
}

void util_id_dallocate(__INT32_TYPE__ id, __UINT64_TYPE__ *key_array)
{
    return id_deallocator(id, key_array);
}