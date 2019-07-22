#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)

struct ethernet_header {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
}; // http://www.tcpdump.org/pcap.html

struct ip_header {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	uint8_t ip_src[4], ip_dst[4]; /* source and dest address */
}; // http://www.tcpdump.org/pcap.html

struct tcp_header {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	u_char th_offx2;	/* data offset, rsvd */
	u_char th_flags;
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
}; // http://www.tcpdump.org/pcap.html

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

void payload_to_hex(const u_char* payload) {
	printf("TCP data : ");
	for(int i=0; i<10; i++) {
		if(payload[i] == '\0') break;
		printf("%X ", payload[i]);
	}
	printf("\n");
}

int main(int argc, char* argv[]) {
	if(argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	struct ethernet_header *ethernet;
	struct ip_header *ip;
	struct tcp_header *tcp;

	uint8_t *ip_src;
	uint8_t *ip_dst;

	uint8_t *mac_src;
	uint8_t *mac_dst;

	u_int size_ip;
	u_int size_tcp;

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if(handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while(true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		const u_char* payload;
		int res = pcap_next_ex(handle, &header, &packet);

		if(res == 0) continue;
		if(res == -1 || res == -2) break;

		ethernet = (struct ethernet_header*)(packet);
		if (ethernet->ether_type != 8) continue;

		mac_src = ethernet->ether_shost;
		mac_dst = ethernet->ether_dhost;

		printf("Source Mac : %02X:%02X:%02X:%02X:%02X:%02X\n", mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
		printf("Destination Mac : %02X:%02X:%02X:%02X:%02X:%02X\n", mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);

		ip = (struct ip_header*)(packet + 14);
		ip_src = ip->ip_src;
		ip_dst = ip->ip_dst;

		printf("IP Source : %d.%d.%d.%d\n", ip_src[0], ip_src[1], ip_src[2], ip_src[3]);
		printf("IP Destination : %d.%d.%d.%d\n", ip_dst[0], ip_dst[1], ip_dst[2], ip_dst[3]);

		size_ip = (((ip)->ip_vhl) & 0x0f) * 4;

		tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp) * 4;

		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		printf("TCP Data size : %d\n", size_tcp);
		payload_to_hex(payload);

		printf("\n");
	}

	pcap_close(handle);
	return 0;
}
