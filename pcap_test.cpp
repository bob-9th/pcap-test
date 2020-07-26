#include <bits/stdc++.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/ethernet.h>

using namespace std;

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
		return -1;
	}

	while (true) {
		pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		auto *eth = (ether_header *) packet;
		ip *_ip = (ip *) (packet + 14);
		if (ntohs(eth->ether_type) == ETHERTYPE_IP && _ip->ip_p == IPPROTO_TCP) {
			cout << "=========== TCP PACKET CAPTURED (" << header->caplen << " bytes) ===========\n\n";
			cout << "Total Bytes: " << header->caplen << " bytes captured\n";
			cout << "Source IP: " << inet_ntoa(_ip->ip_src) << ", Source Mac: "
			     << ether_ntoa((ether_addr *) eth->ether_shost) << "\n";
			cout << "Dest IP: " << inet_ntoa(_ip->ip_dst) << ", Dest Mac: "
			     << ether_ntoa((ether_addr *) eth->ether_dhost) << "\n";

			auto *tcp = (tcphdr *) (packet + 14 + sizeof(ip));
			cout << "Source Port: " << ntohs(tcp->th_sport) << ", Dest Port: " << ntohs(tcp->th_dport) << "\n";

			auto *data = packet + 14 + sizeof(ip) + sizeof(tcphdr) + 12;
			int len = max(0UL, ntohs(_ip->ip_len) - sizeof(ip) - sizeof(tcphdr) - 12);
			cout << "TCP Payload (" << len << " bytes): " << (len ? "" : "<empty>");

			ios prev(NULL);
            prev.copyfmt(cout);

            cout << setfill('0') << hex;
			for (int i = 0; i < min(16, len); i++) {
				cout << setw(2) << (int) data[i] << " ";
			}

            cout.copyfmt(prev);
			cout <<  "\n\n================= [DUMP END] =================\n\n";
		}
	}

	pcap_close(handle);
}
