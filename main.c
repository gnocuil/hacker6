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
char target_ipv4_addr_name[100];
//char device_name[100];
unsigned short dst_port = 6668;
//unsigned short src_port = 6667;
int ipv6_fd;
struct sockaddr_in6 dest;

static void usage()
{
	printf("Usage : hacker6 [options] <target_ipv4_addr>\n");
	printf("            options:  -n <count>         default value: 0\n");
	printf("                      -l <packet_len>    default value: 1400\n");
}

void init_socket()
{
    if ((ipv6_fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr, "Failed to create sockfd!\n");
        exit(1);
    }
    
    memset(&dest, 0, sizeof(dest));
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(dst_port);
    char addr[200] = {0};
    sprintf(addr, "2001:da8:200:900e:0:5efe:%s", target_ipv4_addr_name);
	if (inet_pton(AF_INET6, addr, &dest.sin6_addr) < 0) {
		fprintf(stderr, "Failed to resolve server_addr : %s\n", addr);
		exit(1);
	}
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
    if (sendto(ipv6_fd, packet, len, 0, (struct sockaddr *)&dest, sizeof(struct sockaddr_in6)) < 0) {
    	fprintf(stderr, "Failed to send!\n");
    	exit(1);
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
//    strcpy(device_name, "eth0");
	int i;
	for (i = 1; i < argc; ++i) {
		if (i + 1 < argc && strcmp(argv[i], "-n") == 0) {
			++i;
			sscanf(argv[i], "%d", &count);
        } else if (i + 1 < argc && strcmp(argv[i], "-l") == 0) {
			++i;
			sscanf(argv[i], "%d", &len);
/*	    } else if (i + 1 < argc && strcmp(argv[i], "-i") == 0) {
			++i;
			strcpy(device_name, argv[i]);*/
	    } else if (i < argc) {
	        strcpy(target_ipv4_addr_name, argv[i]);
	        printf("target ipv4 addr : %s\n", target_ipv4_addr_name);
		} else {//config-interface
			usage();
			return 0;
		}
	}
	if (strlen(target_ipv4_addr_name) == 0) {
	    usage();
	    return 0;
	}
    printf("count=%d\n", count);
    init_socket();
    for (i = 0; i < count || count <= 0; ++i) {
        sendpacket();
    }
}
