#include <stdio.h>
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
#include "ssl_alerts.h"
#include "handshake.h"

#define endstream endl<<"-> "
#define IFACE_NAME 100
#define SIZE_UDP 8

using namespace std;

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);
void payload_analyze(const u_char *packet, struct pcap_pkthdr packet_header);
int tcp_payload(const u_char *packet, int offset);
int udp_payload(const u_char *packet, int offset);
void print_ip(struct sniff_ip*);
void endpacket();
void analyze_ssl(const u_char *ssl, int payload_len);
void manage_handshake(const u_char *, int);
void manage_alert(const u_char *, int);
void manage_data(const u_char *, int);
void manage_ccs(const u_char *, int);

int main(int argc, char **argv)
{
  unsigned int packet_counter=0;
  struct pcap_pkthdr *header;
  const u_char *body;
  const u_char *packet;
  int ret;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <pcap>\n", argv[0]);
    exit(1);
  }

  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  handle = pcap_open_offline(argv[1], errbuf);

  if (handle == NULL) {
    fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf);
    return(2);
  }

  while ((ret = pcap_next_ex(handle, &header, &body))==1) {
    print_packet_info(body, *header);
    payload_analyze(body, *header);
  }
  pcap_close(handle);

  return 0;
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
    cout<<"TCP packet"<<endl;
    if(protocol_header_len<20) {
      cout<<"Invalid packet size"<<endl;
      endpacket();
      return;
    }
    break;

    default:
    cout<<"Currently analyzing only TCP protocols"<<endl;
    endpacket();
    return;
  }

  total_header_len = eth_header_len + ip_header_len + protocol_header_len; // Total offset for payload
  payload_len = packet_header.len - total_header_len; // Payload length

  int tcp_off = eth_header_len + ip_header_len;

  int ports = *(int*)(packet+tcp_off);
  int src_port = (ports&0x000000FF)<<8 | (ports&0x0000FF00)>>8;
  cout<<"Source Port: "<<src_port<<endl;

  int dst_port = (ports&0x00FF0000)>>8 | (ports&0xFF000000)>>24;
  cout<<"Destination Port: "<<dst_port<<endl;

  if(src_port==443 || dst_port==443) {
    cout<<"SSL encryption!"<<endl;
    analyze_ssl(packet+tcp_off+protocol_header_len, payload_len);
  }


  if(ip_header_len<20 ||  payload_len < 0) {
    cout<<"Invalid packet size"<<endl;
    endpacket();
    return;
  }

  payload = packet + total_header_len; // Payload starting location

  //
  // cout<<"Total header size: "<<total_header_len<<"bytes"<<endl;
  // cout<<"Ethernet header length: "<<eth_header_len<<"bytes"<<endl;
  // cout<<"IP header length: "<<ip_header_len<<"bytes"<<endl;
  // cout<<protocol_name<<" header length: "<<protocol_header_len<<"bytes"<<endl;
  // cout<<endl<<"Payload length is: "<<payload_len<<"bytes"<<endl;
  //

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

void analyze_ssl(const u_char *ssl, int payload_len) {
  int parsed = 0;
  while(payload_len-parsed > 0) {
    cout<<endl;
    // print_payload(ssl, payload_len);
    int type, version, length;
    type = (*(int *)ssl&0x00FF);
    version = *(int *)(ssl+1) & 0xFFFF;
    version = ((version&0xFF00)>>8) | ((version&0x00FF)<<8);
    length = *(int *)(ssl+3) & 0xFFFF;
    length = ((length&0xFF00)>>8) | ((length&0x00FF)<<8);
    parsed += (length + 5);
    const u_char *ssl_body = ssl + 5;
    ssl = ssl + length + 5;

    cout<<"Version: ";
    switch (version) {
      case 0x0300:
      cout<<"SSL 3.0"<<endl;
      break;
      case 0x0301:
      cout<<"TLS 1.0"<<endl;
      break;
      case 0x0302:
      cout<<"TLS 1.1"<<endl;
      break;
      case 0x0303:
      cout<<"TLS 1.2"<<endl;
      break;
      default:
      cout<<"failed to decode"<<endl;
      break;
    }

    cout<<"Length: "<<length<<endl;

    cout<<"TYPE: ";
    switch (type) {
      case 0x14:
      manage_ccs(ssl_body, length);
      break;
      case 0x15:
      manage_alert(ssl_body, length);
      break;
      case 0x16:
      manage_handshake(ssl_body, length);
      break;
      case 0x17:
      manage_data(ssl_body, length);
      break;
      default:
      cout<<"failed to decode"<<endl;
      break;
    }
    cout<<endl;
  }
  return;
}

void manage_alert(const u_char *alert, int length)
{
  cout<<"ALERT"<<endl;
  short int severity = (*(short int *)alert & 0x00FF);
  switch (severity) {
    case 0x01:
    cout<<"Warning"<<endl;
    break;
    case 0x02:
    cout<<"Fatal"<<endl;
    break;
    default:
    cout<<"Encrypted alert"<<endl;
    return;
  }

  short int description = (*(short int *)alert & 0xFF00) >> 8;
  print_alert(description);
  return;
}

void manage_data(const u_char *data, int length)
{
  cout<<"APPLICATION_DATA"<<endl;
  // print_payload(data, length);
  return;
}

void manage_handshake(const u_char *handshake, int length)
{
  cout<<"HANDSHAKE"<<endl;
  handshake_type(handshake, length);
}

void manage_ccs(const u_char *ccs, int length) {
  cout<<"CHANGE_CIPHER_SPEC"<<endl;
  return;
}
