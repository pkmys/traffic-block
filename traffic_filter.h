#ifndef _TRAFFIC_FILTER_H
#define _TRAFFIC_FILTER_H 

#include <inttypes.h>


#define DEVICE_INTF_NAME "tfdev"
#define DEVICE_MAJOR_NUM 121
#define MAX_KEY_LEN 64

/**************************************************************
 *                                                            *
 *                          TYPEDEFS                          *
 *                                                            *
 **************************************************************/
typedef struct local_rule{
    uint8_t  in;
    uint16_t rule_no;
    uint32_t src_ip;
    uint32_t src_mask;
    uint32_t dst_ip;
    uint32_t dst_mask;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;    

} local_rule_t;

typedef struct tf_key{
    uint32_t key_id;
    unsigned char key[MAX_KEY_LEN]; 
} tf_key_t;

/* Mode of an instruction */
typedef enum ops_mode {
	MFW_NONE = 0,
	MFW_ADD_RULE = 1,
    MFW_ADD_KEY = 2,
	MFW_REMOVE_RULE = 3,
    MFW_REMOVE_KEY = 4,
	MFW_VIEW_RULE = 5,
    MFW_VIEW_KEYS =6
} ops_mode_t;

/* Control instruction */
typedef struct tf_ctl_rule {
	ops_mode_t mode;
	local_rule_t rule;
} tf_ctl_rule_t;

typedef struct tf_ctl_key {
    ops_mode_t mode;
    tf_key_t key;
} tf_ctl_key_t;



static struct option long_options[] = {     /* Long option configuration */
                                        {"in",          no_argument,            0,  'i'},
                                        {"out",         no_argument,            0,  'o'},
                                        {"s_ip",        required_argument,      0,  's'},
                                        {"s_mask",      required_argument,      0,  'm'},
                                        {"s_port",      required_argument,      0,  'p'},
                                        {"d_ip",        required_argument,      0,  'd'},
                                        {"d_mask",      required_argument,      0,  'n'},
                                        {"d_port",      required_argument,      0,  'q'},
                                        {"proto",       required_argument,      0,  'c'},
                                        {"add_key",     required_argument,      0,  'k'},
                                        {"add_rule",    no_argument,            0,  'a'},
                                        {"remove_rule", required_argument,      0,  'x'},
                                        {"remove_key",  required_argument,      0,  'X'},
                                        {"view_rule",   no_argument,            0,  'R'},
                                        {"view_key",    no_argument,            0,  'K'},
                                        {"help",        no_argument,            0,  'h'},
                                        {0, 0, 0, 0}
                                    };

#endif /* _TRAFFIC_FILTER_H*/