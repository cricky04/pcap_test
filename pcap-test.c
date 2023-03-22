#include <pcap.h>
#include <libnet.h>

#include<string.h>
#include<stdlib.h>

#include <stdbool.h>
#include <stdio.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		// parse packet
		const struct libnet_ethernet_hdr *ethernet = (const struct libnet_ethernet_hdr *) packet;
		const struct libnet_ipv4_hdr * ipv4 = (const struct libnet_ipv4_hdr *)(ethernet + sizeof(*ethernet));
		const struct libnet_tcp_hdr * tcp = (const struct libnet_tcp_hdr *)(ipv4 + sizeof(*ipv4));
		
		// check packet type : 0800
		if(ntohs(hdr->ether_type) != 0x800)
		{
			printf("wrong packet type");
			exit(0);
		}

		// ethernet header src/dst mac
		printf("Ethernet Header Source MAC : %2x.%2x.%2x.%2x.%2x.%2x\n
				Ethernet Header Destination MAC : %2x.%2x.%2x.%2x.%2x.%2x\n", ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2], ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5],
				ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2], ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]);

		// IP header src/dst ip
		printf("IP Header Source IP : ")

		printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}
