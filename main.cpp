#include <iostream>
#include <pcap.h>
#include <cstring>
#include <cstdlib>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include "packet_structures.h"
#include "print_payload.h"

#define endstream endl<<"-> "
#define IFACE_NAME 100
#define SIZE_UDP 8
using namespace std;

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
);
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);
void payload_analyze(const u_char *packet, struct pcap_pkthdr packet_header);
int tcp_payload(const u_char *packet, int offset);
int udp_payload(const u_char *packet, int offset);
void print_ip(struct sniff_ip*);
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
	int timeout_limit = 1000;
	int iface_sel, i, lookup_return_code;
  struct bpf_program filter;
  char filter_exp[] = "";

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

	handle = pcap_create(dev, errbuf);

  if (pcap_can_set_rfmon(handle) == 0) {
    cerr<<"Cannot set monitor mode. "<<pcap_geterr(handle)<<endl;
    exit(-1);
  }

  pcap_set_promisc(handle, promisc);
  pcap_set_snaplen(handle, 2048);
  pcap_set_timeout(handle, timeout_limit);

  if (pcap_activate(handle) !=0 ) {
    cerr<<"Error activating capture handle. "<<pcap_geterr(handle)<<endl;
    exit(-1);
  }


  if(pcap_compile(handle, &filter, filter_exp, 0, subnet_mask_raw)==-1) {
    cerr<<"Bad filter - "<<pcap_geterr(handle)<<endl;
    exit(-1);
  }

  if(pcap_setfilter(handle, &filter) == -1) {
    cerr<<"Error setting the filter - "<<pcap_geterr(handle)<<endl;
    exit(-1);
  }

	pcap_loop(handle, 0, my_packet_handler, NULL);

  pcap_close(handle);

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
  int payload_len;
  int protocol_header_len;
  int total_header_len;
  char protocol_name[10];

  struct sniff_ethernet *ethernet;
  struct sniff_ip *ip;

  ethernet = (struct sniff_ethernet*) packet;

  ip_header = packet + eth_header_len;
  ip = (struct sniff_ip*) ip_header;
  print_ip(ip);
  ip_header_len = ((*ip_header) & 0x0F); //Lower nibble on IP header at  stating byte

  ip_header_len = ip_header_len * 4; // ?? Something to do with 32 bit segments so mul by 4

  switch (*(ip_header+9)) { // 10th byte represents protocol
    case IPPROTO_TCP:
      strcpy(protocol_name, "TCP");
      protocol_header_len = tcp_payload(packet, eth_header_len + ip_header_len);
      if(protocol_header_len<20) {
        cout<<"Invalid packet size"<<endl;
        endpacket();
        return;
      }
      break;

    case IPPROTO_UDP:
      strcpy(protocol_name, "UDP");
      protocol_header_len = udp_payload(packet, eth_header_len + ip_header_len);
      break;

    default:
      cout<<"Currently analyzing only TCP protocols"<<endl;
      endpacket();
      return;
  }

  total_header_len = eth_header_len + ip_header_len + protocol_header_len; // Total offset for payload
  payload_len = packet_header.len - total_header_len; // Payload length

  if(ip_header_len<20 ||  payload_len < 0) {
    cout<<"Invalid packet size"<<endl;
    endpacket();
    return;
  }

  payload = packet + total_header_len; // Payload starting location

  cout<<"Total header size: "<<total_header_len<<"bytes"<<endl;
  cout<<"Ethernet header length: "<<eth_header_len<<"bytes"<<endl;
  cout<<"IP header length: "<<ip_header_len<<"bytes"<<endl;
  cout<<protocol_name<<" header length: "<<protocol_header_len<<"bytes"<<endl;
  cout<<endl<<"Payload length is: "<<payload_len<<"bytes"<<endl;

  print_payload(payload, payload_len);

  endpacket();
  return;

}


int tcp_payload(const u_char *packet, int offset) {
  const u_char *tcp_header = packet + offset;
  struct sniff_tcp *tcp = (struct sniff_tcp*) tcp_header;

  int tcp_header_len = ((*(tcp_header + 12)) & 0xF0) >> 4; // Offset 12 with upper nibble has header length

  tcp_header_len *= 4; // ?? again something with 32 bit segments
  return tcp_header_len;
}

int udp_payload(const u_char *packet, int offset) {
  const u_char *udp_header = packet + offset;
  struct sniff_udp *udp = (struct sniff_udp*) udp_header;
  return SIZE_UDP;
}

void print_ip(struct sniff_ip* ip) {
  char ipaddr[13]; // IP
  struct in_addr address;
  struct in_addr from = ip->ip_src;
  struct in_addr to = ip->ip_dst;
  address = from;
  strcpy(ipaddr, inet_ntoa(address));
  if(ipaddr == NULL) {
    cerr<<"Couldn't get ip address of the device"<<endl;
    exit(-1);
  }
  cout<<"Source ip: "<<ipaddr<<endl;
  address = to;
  strcpy(ipaddr, inet_ntoa(address));
  if(ipaddr == NULL) {
    cerr<<"Couldn't get ip address of the device"<<endl;
    exit(-1);
  }
  cout<<"Destination ip: "<<ipaddr<<endl;
  return;
}


void endpacket() {
  cout<<endl;
  for(int i=0;i<64;i++)
    cout<<"-";
  cout<<endl;
}
