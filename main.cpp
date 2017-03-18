#include <iostream>
#include <pcap.h>
#include <cstring>
#include <cstdlib>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#define endstream endl<<"-> ";
#define IFACE_NAME 100

using namespace std;

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
);
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);
void payload_analyze(const u_char *packet, struct pcap_pkthdr packet_header);
void endpacket();


int main(int argc, char const *argv[]) {

	char errbuf[PCAP_ERRBUF_SIZE]; //Error Buffer for pcap
	char dev[IFACE_NAME]; //Interface name
	pcap_if_t *interfaces, *temp; // Interfaces
	pcap_t *handle; // capture handle
	bpf_u_int32 ip_raw, subnet_mask_raw; //Raw ip and subnet mask
	struct in_addr address; // For converion from raw int ip to dotted ip
	char ip[13]; // IP
	char subnet_mask[13]; //Subnet mask
	const u_char *packet;
	struct pcap_pkthdr packet_header;
	int promisc = 1;
	int timeout_limit = 10000;
	int iface_sel, i, lookup_return_code;

	if(pcap_findalldevs(&interfaces, errbuf)==-1) {
		cerr<<"Couldn't recognize network interfaces"<<endl;
		cerr<<errbuf<<endl;
		exit(-1);
	}

	for(temp=interfaces, i=1;temp;temp=temp->next, i++) {
		cout<<i<<": "<<temp->name<<endl;
	}

	cout<<"Choose interface"<<endstream;	// Selecting an interface out of available
	cin>>iface_sel;
	while(iface_sel-1)
		interfaces=interfaces->next, iface_sel--;
	strcpy(dev, interfaces->name);

	lookup_return_code = pcap_lookupnet(
		dev,
		&ip_raw,
		&subnet_mask_raw,
		errbuf
	);

	if(lookup_return_code==-1) {
		cout<<"Lookup failed"<<endl;
		cerr<<errbuf<<endl;
		exit(-1);
	}

	// Conversion from raw to dotted network address

	address.s_addr = ip_raw;
	strcpy(ip, inet_ntoa(address));
	if(ip == NULL) {
		cerr<<"Couldn't get ip address of the device"<<endl;
		exit(-1);
	}

	address.s_addr = subnet_mask_raw;
	strcpy(subnet_mask, inet_ntoa(address));
	if(ip == NULL) {
		cerr<<"Couldn't get subnet mask of the device"<<endl;
		exit(-1);
	}

	cout<<"Device: "<<dev<<endl;
	cout<<"IP: "<<ip<<endl;
	cout<<"Subnet mask: "<<subnet_mask<<endl;
	cout<<endl;

	handle = pcap_open_live(
		dev,
		BUFSIZ,
		promisc,
		timeout_limit,
		errbuf
	);

	pcap_loop(handle, 0, my_packet_handler, NULL);

  return 0;

}


void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body
)
{
    print_packet_info(packet_body, *packet_header);
    payload_analyze(packet_body, *packet_header);
    return;
}


void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    cout<<"Packet capture length: "<<packet_header.caplen<<endl;
    cout<<"Packet total length: "<<packet_header.len<<endl;

    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

		if(ntohs(eth_header->ether_type) == ETHERTYPE_IP)
			cout<<"IP packet"<<endl;
		else if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP)
			cout<<"ARP packet"<<endl;
		else if(ntohs(eth_header->ether_type) == ETHERTYPE_REVARP)
			cout<<"Reverse ARP packet"<<endl;
		cout<<endl;

}


void payload_analyze(const u_char *packet, struct pcap_pkthdr packet_header) {
  struct ether_header *eth_header;
  eth_header = (struct ether_header *) packet;

  if(ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
    cout<<"Currently inspecting only IP packets"<<endl;
    endpacket();
    return;
  }

  const u_char *ip_header; // IP header from captured packet
  const u_char *tcp_header; // TCP header from captured packet
  const u_char *payload; // Actual payload from captured packet

  int eth_header_len = 14; // Stanard onstant source_MAC(6) + dest_MAC(6) + ether_header type (2) = 14
  int ip_header_len;
  int tcp_header_len;
  int payload_len;
  int total_header_len;

  ip_header = packet + eth_header_len;

  ip_header_len = ((*ip_header) & 0x0F); //Lower nibble on IP header at  stating byte

  ip_header_len *= 4; // ?? Something to do with 32 bit segments so mul by 4

  if(*(ip_header+9) != IPPROTO_TCP) { // 10th byte represents protocol
    cout<<"Currently analyzing only TCP protocols"<<endl;
    endpacket();
    return;
  }

  tcp_header = packet + eth_header_len + ip_header_len;

  tcp_header_len = ((*(tcp_header) + 12) & 0xF0) >> 4; // Offset 12 with upper nibble has header length

  tcp_header_len *= 4; // ?? again something with 32 bit segments

  total_header_len = eth_header_len + ip_header_len + tcp_header_len; // Total offset for payload
  cout<<"Total header size: "<<total_header_len<<"bytes"<<endl;
  cout<<"Ethernet header length: "<<eth_header_len<<"bytes"<<endl;
  cout<<"IP header length: "<<ip_header_len<<"bytes"<<endl;
  cout<<"TCP header length: "<<tcp_header_len<<"bytes"<<endl;

  payload_len = packet_header.len - total_header_len; // Payload length
  cout<<endl<<"Payload length is: "<<payload_len<<"bytes"<<endl;

  payload = packet + total_header_len; // Payload starting location
  printf("Memory address where payload begins: %p\n\n", payload);

  endpacket();
  return;

}


void endpacket() {
  for(int i=0;i<64;i++)
    cout<<"-";
  cout<<endl;
}
