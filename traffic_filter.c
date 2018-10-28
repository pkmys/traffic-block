#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "traffic_filter.h"

#define PORT_NUM_MAX USHRT_MAX
#define RD_GEN_TABLE _IOW(DEVICE_MAJOR_NUM, 1, uint32_t *)
#define RD_KEY_TABLE _IOW(DEVICE_MAJOR_NUM, 2, uint32_t *)
#define WR_GEN_TABLE _IOW(DEVICE_MAJOR_NUM, 3, uint32_t *)
#define WR_KEY_TABLE _IOW(DEVICE_MAJOR_NUM, 4, uint32_t *)

/*
 * The function prints usage and parameters.
 */
static void print_usage(void)
{
	printf("Usage: tf RULE_OPTIONS..\n"
		   "traffic filter implements an exact match algorithm, where "
		   "unspecified options are ignored.\n"
		   "-i --in             input\n"
		   "-o --out            output\n"
		   "-s --s_ip IPADDR    source ip address\n"
		   "-m --s_mask MASK    source mask\n"
		   "-p --s_port PORT    source port\n"
		   "-d --d_ip IPADDR    destination ip address\n"
		   "-n --d_mask MASK    destination mask\n"
		   "-q --d_port PORT    destination port\n"
		   "-c --proto PROTO    protocol\n"
		   "-a --add            add a rule\n"
		   "-r --remove         remove a rule\n"
		   "-v --view           view rules\n"
		   "-h --help           this usage\n");
}

/*
 * The function sends a command to a MiniFirewall module via a device file.
 */
static void send_instruction_rule(tf_ctl_rule_t *ctl)
{
	int fp;
	int byte_count;

	fp = open(DEVICE_INTF_NAME, O_WRONLY);
	if (fp < 0)
	{
		printf("An device file (%s) cannot be opened.\n", DEVICE_INTF_NAME);
		return;
	}
	ioctl(fp, WR_GEN_TABLE, 0);
	byte_count = write(fp, ctl, sizeof(*ctl));
	if (byte_count != sizeof(*ctl))
		printf("Write process is incomplete. Please try again.\n");

	close(fp);
}

static void send_instruction_key(tf_ctl_key_t *ctl)
{
	int fp;
	int byte_count;

	fp = open(DEVICE_INTF_NAME, O_WRONLY);
	if (fp < 0)
	{
		printf("An device file (%s) cannot be opened.\n", DEVICE_INTF_NAME);
		return;
	}
	ioctl(fp, WR_KEY_TABLE, 0);
	byte_count = write(fp, ctl, sizeof(*ctl));
	if (byte_count != sizeof(*ctl))
		printf("Write process is incomplete. Please try again.\n");

	close(fp);
}

/*
 * The function prints all existing rules, installed in the kernel module.
 */
static void view_rules(int mode)
{
	int fp;
	char *buffer;
	int byte_count;
	struct in_addr addr;
	local_rule_t *rule;
	tf_key_t *key;

	fp = open(DEVICE_INTF_NAME, O_RDONLY);
	if (fp < 0)
	{
		printf("An device file (%s) cannot be opened.\n",
			   DEVICE_INTF_NAME);
		return;
	}

	if (mode == MFW_VIEW_RULE)
	{
		buffer = (char *)malloc(sizeof(*rule));
		if (buffer == NULL)
		{
			printf("Rule cannot be printed due to insufficient memory\n");
			return;
		}
		ioctl(fp, RD_GEN_TABLE, 0);
		/* Each rule is printed line-by-line. */
		printf("\n\n-----+-----+------------------+------------------+--------+"
			   "------------------+------------------+--------+-------\n");
		printf(" Id  | I/O |  S_Addr          | S_Mask           | S_Port |"
			   " D_Addr           | D_Mask           | D_Port | Proto \n");
		printf("-----+-----+------------------+------------------+--------+"
			   "------------------+------------------+--------+-------\n");
		while ((byte_count = read(fp, buffer, sizeof(local_rule_t))) > 0)
		{
			rule = (local_rule_t *)buffer;
			printf(" %-3d ", rule->rule_no);
			printf("| %-3s ", rule->in ? "In" : "Out");
			addr.s_addr = rule->src_ip;
			printf("| %-15s  ", inet_ntoa(addr));
			addr.s_addr = rule->src_mask;
			printf("| %-15s  ", inet_ntoa(addr));
			printf("| %-5d  ", ntohs(rule->src_port));
			addr.s_addr = rule->dst_ip;
			printf("| %-15s  ", inet_ntoa(addr));
			addr.s_addr = rule->dst_mask;
			printf("| %-15s  ", inet_ntoa(addr));
			printf("| %-5d  ", ntohs(rule->dst_port));
			printf("|  %-3d  \n", rule->protocol);
		}
		printf("-----+-----+------------------+------------------+--------+"
			   "------------------+------------------+--------+-------\n\n\n");
	}
	else if (mode == MFW_VIEW_KEYS){
		buffer = (char *)malloc(sizeof(*key));
		if (buffer == NULL)
		{
			printf("Keys cannot be printed due to insufficient memory\n");
			return;
		}
		ioctl(fp, RD_KEY_TABLE, 0);

		printf("--------+-----------------------------------\n");
		printf(" key id |                 key               \n");
		printf("--------+-----------------------------------\n");

		while ((byte_count = read(fp, buffer, sizeof(tf_key_t))) > 0)
		{
			key = (tf_key_t *)buffer;
			printf("  %-4d  ", key->key_id);
			printf("|  %s\n", key->key);
		}
		printf("--------+-----------------------------------\n");

	}
	free(buffer);
	close(fp);
}

/*
 * The function parses a string and checks its range.
 */
static int64_t parse_number(const char *str, uint32_t min_val, uint32_t max_val)
{
	uint32_t num;
	char *end;

	num = strtol(str, &end, 10);
	if (end == str || (num > max_val) || (num < min_val))
		return -1;

	return num;
}

int main(int argc, char *argv[])
{
	tf_ctl_rule_t ctl = {};
	tf_ctl_key_t kctl ={};
	int opt;
	int64_t lnum;
	int opt_index;
	struct in_addr addr;

	if (argc == 1)
	{
		print_usage();
		return 0;
	}

	ctl.mode = MFW_NONE;
	ctl.rule.in = 2;
	while (1)
	{
		opt_index = 0;
		opt = getopt_long(argc, argv, "ios:m:p:d:n:q:c:k:ax:X:RKh",
						  long_options, &opt_index);
		if (opt == -1)
		{
			break;
		}

		switch (opt)
		{
		case 'i': /* Inbound rule */
			if (ctl.rule.in == 0)
			{
				printf("Please select either In or Out\n");
				return -1;
			}
			ctl.rule.in = 1;
			break;
		case 'o': /* Outbound rule */
			if (ctl.rule.in == 1)
			{
				printf("Please select either In or Out\n");
				return -1;
			}
			ctl.rule.in = 0;
			break;
		case 's': /* Source ip address */
			if (inet_aton(optarg, &addr) == 0)
			{
				printf("Invalid source ip address\n");
				return -1;
			}
			ctl.rule.src_ip = addr.s_addr;
			break;
		case 'm': /* Source subnet mask */
			if (inet_aton(optarg, &addr) == 0)
			{
				printf("Invalid source subnet mask\n");
				return -1;
			}
			ctl.rule.src_mask = addr.s_addr;
			break;
		case 'p': /* Source port number */
			lnum = parse_number(optarg, 0, USHRT_MAX);
			if (lnum < 0)
			{
				printf("Invalid source port number\n");
				return -1;
			}
			ctl.rule.src_port = htons((uint16_t)lnum);
			break;
		case 'd': /* Destination ip address */
			if (inet_aton(optarg, &addr) == 0)
			{
				printf("Invalid destination ip address\n");
				return -1;
			}
			ctl.rule.dst_ip = addr.s_addr;
			break;
		case 'n': /* Destination subnet mask */
			if (inet_aton(optarg, &addr) == 0)
			{
				printf("Invalid destination subnet mask\n");
				return -1;
			}
			ctl.rule.dst_mask = addr.s_addr;
			break;
		case 'q': /* Destination port number */
			lnum = parse_number(optarg, 0, USHRT_MAX);
			if (lnum < 0)
			{
				printf("Invalid destination port number\n");
				return -1;
			}
			ctl.rule.dst_port = htons((uint16_t)lnum);
			break;
		case 'c': /* Protocol number */
			lnum = parse_number(optarg, 0, UCHAR_MAX);
			if (lnum < 0 ||
				!(lnum == 0 ||
				  lnum == IPPROTO_TCP ||
				  lnum == IPPROTO_UDP))
			{
				printf("Invalid protocol number\n");
				return -1;
			}
			ctl.rule.protocol = (uint8_t)lnum;
			break;
		case 'a': /* Add rule */
			if (ctl.mode != MFW_NONE)
			{
				printf("Only one mode can be selected.\n");
				return -1;
			}
			ctl.mode = MFW_ADD_RULE;
			break;
		case 'k':
			if(strlen(optarg) > MAX_KEY_LEN -1){
				printf("Max key length of 63 is allowed\n");
				return -1;
			}
			ctl.mode = MFW_ADD_KEY;
			kctl.mode = MFW_ADD_KEY;
			strcpy(kctl.key.key, optarg);
			break;
		case 'r': /* Remove rule */
			if (ctl.mode != MFW_NONE)
			{
				printf("Only one mode can be selected.\n");
				return -1;
			}
			ctl.mode = MFW_REMOVE_RULE;
			break;
		case 'R': /* View rules */
			if (ctl.mode != MFW_NONE)
			{
				printf("Only one mode can be selected.\n");
				return -1;
			}
			ctl.mode = MFW_VIEW_RULE;
			break;
		case 'K': /* View keys */
			if (ctl.mode != MFW_NONE)
			{
				printf("Only one mode can be selected.\n");
				return -1;
			}
			ctl.mode = MFW_VIEW_KEYS;
			break;
		case 'x':
			if (ctl.mode != MFW_NONE)
			{
				printf("Only one mode can be selected.\n");
				return -1;
			}
			ctl.mode = MFW_REMOVE_RULE;
			ctl.rule.rule_no = (uint16_t)parse_number(optarg, 0, UCHAR_MAX);
			break;
		case 'X':
			ctl.mode = MFW_REMOVE_KEY;
			kctl.mode = MFW_REMOVE_KEY;
			kctl.key.key_id = (uint16_t)parse_number(optarg, 0, UCHAR_MAX);
			break;
		case 'h':
		case '?':
		default:
			print_usage();
			return -1;
		}
	}

	if (ctl.mode == MFW_NONE)
	{
		printf("Please specify mode --(add|remove|view)\n");
		return -1;
	}

	switch (ctl.mode)
	{
	case MFW_ADD_RULE:
	case MFW_REMOVE_RULE:
		send_instruction_rule(&ctl);
		break;
	case MFW_ADD_KEY:
	case MFW_REMOVE_KEY:
		send_instruction_key(&kctl);
		break;
	case MFW_VIEW_RULE:
		view_rules(MFW_VIEW_RULE);
		break;
	case MFW_VIEW_KEYS:
		view_rules(MFW_VIEW_KEYS);
		break;
	default:
		return 0;
	}
	return 0;
}
