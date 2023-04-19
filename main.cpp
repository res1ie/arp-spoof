#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}
uint32_t parseip(const char* str) {
	uint8_t temp[4];
	int res = sscanf(str, "%hhu.%hhu.%hhu.%hhu", temp+3, temp+2, temp+1, temp);
	if (res != 4) {
		fprintf(stderr, "parseip sscanf return %d r=%s\n", res, str);
		exit(-1);
	}
	return *(uint32_t*)temp;
}


void sendpacket(pcap_t* handle,Mac eth_dmac,Mac eth_smac,Mac arp_smac,Ip arp_sip,Mac arp_tmac,Ip arp_tip,uint16_t op) {
	EthArpPacket packet;

	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(op);
	packet.arp_.smac_ = arp_smac;
	packet.arp_.sip_ = htonl(arp_sip);
	packet.arp_.tmac_ = arp_tmac;
	packet.arp_.tip_ = htonl(arp_tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void recvpacket(pcap_t* handle,pcap_pkthdr** pheader,const EthArpPacket** pppacket) {//copied from pcap-test.c
	int res = pcap_next_ex(handle, pheader, reinterpret_cast<const u_char**>(pppacket));
	if (res == 0) return;
	if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
		fprintf(stderr,"pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
		exit(-1);
	}
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc&1 ) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	//get addresses 
	pcap_if_t* devp;
	if(pcap_findalldevs(&devp,errbuf)){
		fprintf(stderr, "couldn't find all device(%s)\n",errbuf); 
	}
	while(devp) {
		if(strcmp(dev,devp->name)==0)
			break;
		devp=devp->next;
	}
	//get MAC
	pcap_addr_t* dev_addr=devp->addresses;
	while(dev_addr&&dev_addr->addr->sa_family!=AF_PACKET) {
		dev_addr=dev_addr->next;
	}
	if(!dev_addr) {
		fprintf(stderr, "couldn't find MAC address\n");
		return -1;
	}
	Mac dev_MAC=Mac((const uint8_t*)(dev_addr->addr->sa_data+10));//sockaddr_ll.sll_addr
	//get IP
	dev_addr=devp->addresses;
	while(dev_addr&&dev_addr->addr->sa_family!=AF_INET) {
		dev_addr=dev_addr->next;
	}
	if(!dev_addr) {
		fprintf(stderr, "couldn't find IP address\n");
		return -1;
	}
	Ip dev_IP=Ip(ntohl(*(uint32_t*)&((sockaddr_in*)(dev_addr->addr))->sin_addr));//casting and ntohl
	pcap_pkthdr* header;
	const EthArpPacket* ppacket;
	for(int i=2;i<argc;i+=2)
	{
		Ip senderIp=Ip(argv[i]);
		Ip targetIp=Ip(argv[i+1]);
		sendpacket(handle,Mac::broadcastMac(),dev_MAC,dev_MAC,dev_IP,Mac::nullMac(),senderIp,ArpHdr::Request);	
		recvpacket(handle,&header,&ppacket);
		Mac senderMac=ppacket->eth_.smac_;
		sendpacket(handle,senderMac,dev_MAC,dev_MAC,targetIp,senderMac,senderIp,ArpHdr::Reply);
	}
	pcap_close(handle);
}
