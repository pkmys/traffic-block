#ifndef _TRAFFIC_FILTER_H
#define _TRAFFIC_FILTER_H 

#include <inttypes.h>

#define DEVICE_INTF_NAME "tfdev"

/**************************************************************
 *                                                            *
 *                          TYPEDEFS                          *
 *                                                            *
 **************************************************************/
typedef struct local_rule{
    uint8_t  in;
    uint32_t src_ip;
    uint32_t src_mask;
    uint32_t dst_ip;
    uint32_t dst_mask;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;    

} local_rule_t;

/* Mode of an instruction */
typedef enum ops_mode {
	MFW_NONE = 0,
	MFW_ADD = 1,
	MFW_REMOVE = 2,
	MFW_VIEW = 3
} ops_mode_t;

/* Control instruction */
typedef struct tf_ctl {
	ops_mode_t mode;
	local_rule_t rule;
} tf_ctl_t;

#endif /* _TRAFFIC_FILTER_H*/