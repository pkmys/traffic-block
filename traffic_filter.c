#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>

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
	printf(	"TB - (Traffic Filter) 0.1.0\n"
		"Usage: tb [arguments]\n"
		"       tb -a <-i/o> [-smpdnqc]             adding ip-port rule\n"
		"       tb -k <filter key>                  adding dns filter key\n"
		"       tb -x <rule id>                     remove ip-port rules\n"
		"       tb -X <key id>                      remove dns key \n"
		"       tb -R|K                             view ip-port rule\n"
		"\nArguments:\n"
		"   -a --add_rule                 add a rule\n"
		"   -i --in                       input\n"
		"   -o --out                      output\n"
		"   -s --s_ip         <ipaddr>    source ip address\n"
		"   -m --s_mask         <mask>    source mask\n"
		"   -p --s_port         <port>    source port\n"
		"   -d --d_ip         <ipaddr>    destination ip address\n"
		"   -n --d_mask         <mask>    destination mask\n"
		"   -q --d_port         <port>    destination port\n"
		"   -c --proto         <proto>    protocol [TCP-6/UDP-17/ALL-default<0>]\n"
		"   -k --add_key     <keyword>    keyword tto block traffic\n"
		"   -R --view_rule                view rule table\n"
		"   -K --view_key                 view key table\n"
		"   -A --view_all                 view all table\n"
		"   -x --remove_rule <rule id>    remove rule with rule id\n"
		"   -X --remove_key   <key id>    remove key with keyid\n"
		"   -v --version                  version info\n"
		"   -h --help                     print usage\n"
		"\nThis  is simple traffic  filtering  program  used for filtering linux\n"
		"network traffic,  currently it  supports  only TCP and UDP protocols.\n"
		"It has  ability to  block matching  source/dest port, ip, network for\n"
		"TCP/UDP connections, moreover it can block dns requests matching with\n"
		"keywords provided by user.\n"
		"\nSend tb bugs to Pawan Kumar <jmppawanhit@gmail.com>\n"
		"Github hom page: <https://github.com/pkmys/>\n"
		"General help using opensource software: <https://opensource.org/osd-annotated>\n");
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
		perror("device file cannot be opened.");
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
		perror("device file cannot be opened.");
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
		perror("device file cannot be opened.");
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
		printf("\n+-----+-----+------------------+------------------+--------+"
			   "------------------+------------------+--------+-------+\n");
		printf("| Id  | I/O |  S_Addr          | S_Mask           | S_Port |"
			   " D_Addr           | D_Mask           | D_Port | Proto |\n");
		printf("+-----+-----+------------------+------------------+--------+"
			   "------------------+------------------+--------+-------+\n");
		while ((byte_count = read(fp, buffer, sizeof(local_rule_t))) > 0)
		{
			rule = (local_rule_t *)buffer;
			printf("| %-3d ", rule->rule_no);
			printf("| %-3s ", rule->in ? "In" : "Out");
			addr.s_addr = rule->src_ip;
			if (rule->src_ip == 0) printf("| %-15s  ", "       -");
			else printf("| %-15s  ", inet_ntoa(addr));
			addr.s_addr = rule->src_mask;
			if(rule->src_mask == 0) printf("| %-15s  ", "       -");
			else printf("| %-15s  ", inet_ntoa(addr));
			if(rule->src_port == 0) printf("| %-5s  ","  -");
			else printf("| %-5d  ", ntohs(rule->src_port));
			addr.s_addr = rule->dst_ip;
			if(rule->dst_ip == 0) printf("| %-15s  ", "       -");
			else printf("| %-15s  ", inet_ntoa(addr));
			addr.s_addr = rule->dst_mask;
			if(rule->dst_mask == 0) printf("| %-15s  ","       -");
			else printf("| %-15s  ", inet_ntoa(addr));
			if(rule->dst_port == 0) printf("| %-5s  ","  -");
			else printf("| %-5d  ", ntohs(rule->dst_port));
			if(rule->protocol == IPPROTO_TCP) printf("|  TCP  |\n");
			else if(rule->protocol == IPPROTO_UDP) printf("|  UDP  |\n");
			else printf("|   -   |\n");
		}
		printf("+-----+-----+------------------+------------------+--------+"
			   "------------------+------------------+--------+-------+\n\n");
	}
	else if (mode == MFW_VIEW_KEYS){
		buffer = (char *)malloc(sizeof(*key));
		if (buffer == NULL)
		{
			printf("Keys cannot be printed due to insufficient memory\n");
			return;
		}
		ioctl(fp, RD_KEY_TABLE, 0);

		printf("+--------+------------------------------------------------------------------+\n");
		printf("| key id |                              key                                 |\n");
		printf("+--------+------------------------------------------------------------------+\n");

		while ((byte_count = read(fp, buffer, sizeof(tf_key_t))) > 0)
		{
			key = (tf_key_t *)buffer;
			printf("|  %-4d  ", key->key_id);
			printf("|  %-63s |\n", key->key);
		}
		printf("+--------+------------------------------------------------------------------+\n");

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
		goto VERSION;
	}

	ctl.mode = MFW_NONE;
	ctl.rule.in = 2;
	while (1)
	{
		opt_index = 0;
		opt = getopt_long(argc, argv, "ios:m:p:d:n:q:c:k:ax:X:RKAhvV",
						  long_options, &opt_index);
		if (opt == -1)
		{
			break;
		}

		switch (opt)
		{
		case 'a': /* Add rule */
			if (ctl.mode != MFW_NONE)
			{
				printf("a:Only one mode can be selected.\n");
				return -1;
			}
			ctl.mode = MFW_ADD_RULE;
			break;
		case 'i': /* Inbound rule */
			if (ctl.rule.in == 0)
			{
				printf("i: Please select either In or Out\n");
				return -1;
			}
			if(ctl.mode != MFW_ADD_RULE){
				printf("i: Option valid with '-a'\n");
				return -1;
			}
			ctl.rule.in = 1;
			break;
		case 'o': /* Outbound rule */
			if (ctl.rule.in == 1)
			{
				printf("o: Please select either In or Out\n");
				return -1;
			}
			if(ctl.mode != MFW_ADD_RULE){
				printf("o: Option valid with '-a'\n");
				return -1;
			}
			ctl.rule.in = 0;
			break;
		case 's': /* Source ip address */
			if(ctl.mode != MFW_ADD_RULE){
				printf("s: Option valid with '-a'\n");
				return -1;
			}
			if (inet_aton(optarg, &addr) == 0)
			{
				printf("s: Invalid source ip address\n");
				return -1;
			}
			ctl.rule.src_ip = addr.s_addr;
			break;
		case 'm': /* Source subnet mask */
			if(ctl.mode != MFW_ADD_RULE){
				printf("m: Option valid with '-a'\n");
				return -1;
			}
			if (inet_aton(optarg, &addr) == 0)
			{
				printf("m: Invalid source subnet mask\n");
				return -1;
			}
			ctl.rule.src_mask = addr.s_addr;
			break;
		case 'p': /* Source port number */
			if(ctl.mode != MFW_ADD_RULE){
				printf("p: Option valid with '-a'\n");
				return -1;
			}
			lnum = parse_number(optarg, 0, USHRT_MAX);
			if (lnum < 0)
			{
				printf("p: Invalid source port number\n");
				return -1;
			}
			ctl.rule.src_port = htons((uint16_t)lnum);
			break;
		case 'd': /* Destination ip address */
			if(ctl.mode != MFW_ADD_RULE){
				printf("d: Option valid with '-a'\n");
				return -1;
			}
			if (inet_aton(optarg, &addr) == 0)
			{
				printf("d: Invalid destination ip address\n");
				return -1;
			}
			ctl.rule.dst_ip = addr.s_addr;
			break;
		case 'n': /* Destination subnet mask */
			if(ctl.mode != MFW_ADD_RULE){
				printf("n: Option valid with '-a'\n");
				return -1;
			}
			if (inet_aton(optarg, &addr) == 0)
			{
				printf("n: Invalid destination subnet mask\n");
				return -1;
			}
			ctl.rule.dst_mask = addr.s_addr;
			break;
		case 'q': /* Destination port number */
			if(ctl.mode != MFW_ADD_RULE){
				printf("q: Option valid with '-a'\n");
				return -1;
			}
			lnum = parse_number(optarg, 0, USHRT_MAX);
			if (lnum < 0)
			{
				printf("q: Invalid destination port number\n");
				return -1;
			}
			ctl.rule.dst_port = htons((uint16_t)lnum);
			break;
		case 'c': /* Protocol number */
			if(ctl.mode != MFW_ADD_RULE){
				printf("c: Option valid with '-a'\n");
				return -1;
			}
			lnum = parse_number(optarg, 0, UCHAR_MAX);
			if (lnum < 0 ||!(lnum == 0 ||
				  lnum == IPPROTO_TCP ||
				  lnum == IPPROTO_UDP))
			{
				printf("c: Invalid protocol number [TCP-6/UDP-17/ALL-default<0>]\n");
				return -1;
			}
			ctl.rule.protocol = (uint8_t)lnum;
			break;
		case 'k':
			if (ctl.mode != MFW_NONE)
			{
				printf("k: Only one mode can be selected.\n");
				return -1;
			}
			if(optarg[0] == '-'){
				printf("tb: option requires an argument -- 'k'\n");
				goto DEFAULT;
			}
			if(strlen(optarg) > MAX_KEY_LEN -1){
				printf("k: Max key length of 63 is allowed, please shorten keyword\n");
				return -1;
			}
			ctl.mode = MFW_ADD_KEY;
			kctl.mode = MFW_ADD_KEY;
			strcpy(kctl.key.key, optarg);
			break;
			ctl.mode = MFW_REMOVE_RULE;
			break;
		case 'R': /* View rules */
			if (ctl.mode != MFW_NONE)
			{
				printf("R: Only one mode can be selected.\n");
				return -1;
			}
			ctl.mode = MFW_VIEW_RULE;
			break;
		case 'K': /* View keys */
			if (ctl.mode != MFW_NONE)
			{
				printf("K: Only one mode can be selected.\n");
				return -1;
			}
			ctl.mode = MFW_VIEW_KEYS;
			break;
		case 'A': /* View keys */
			if (ctl.mode != MFW_NONE)
			{
				printf("A: Only one mode can be selected.\n");
				return -1;
			}
			ctl.mode = MFW_VIEW_ALL;
			break;
		case 'x':
			if (ctl.mode != MFW_NONE)
			{
				printf("x: Only one mode can be selected.\n");
				return -1;
			}
			ctl.mode = MFW_REMOVE_RULE;
			ctl.rule.rule_no = (uint16_t)parse_number(optarg, 0, UCHAR_MAX);
			break;
		case 'X':
			if (ctl.mode != MFW_NONE)
			{
				printf("X: Only one mode can be selected.\n");
				return -1;
			}
			ctl.mode = MFW_REMOVE_KEY;
			kctl.mode = MFW_REMOVE_KEY;
			kctl.key.key_id = (uint16_t)parse_number(optarg, 0, UCHAR_MAX);
			break;
		case 'v':
		case 'V':
VERSION:
			printf(	"TB - (Traffic Filter) 0.1.0\n"
				"Copyright (C) 2018 Pawan Kumar.\n"
				"License MIT: MIT opensource <https://opensource.org/licenses/MIT>.\n"
				"This is free software: you are free to change and redistribute it.\n"
				"There is NO WARRANTY, to the extent permitted by law.\n"
				"\nWritten by Pawan Kumar.\n");
			return 0;
		case 'h':
			print_usage();
			return 0;
		case '?':
DEFAULT:
		default:
			printf("Try 'tb --help' for more information.\n");
			return -1;
		}
	}

	if (ctl.mode == MFW_NONE)
	{
		printf("Please specify mode -- 'add|remove|view'\n");
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
	case MFW_VIEW_ALL:
		view_rules(MFW_VIEW_RULE);
		view_rules(MFW_VIEW_KEYS);
		break;
	default:
		return 0;
	}
	return 0;
}
