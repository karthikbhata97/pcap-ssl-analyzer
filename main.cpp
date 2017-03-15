#include<iostream>
#include<pcap.h>
#include<cstring>
#include<cstdlib>
#include <arpa/inet.h>
#define endstream endl<<"-> ";
#define IFACE_NAME 100
using namespace std;

int main(int argc, char const *argv[]) {

	char errbuf[PCAP_ERRBUF_SIZE]; //Error Buffer for pcap
	char dev[IFACE_NAME]; //Interface name
	pcap_if_t *interfaces, *temp; // Interfaces
	pcap_t *pcap; // -----
	bpf_u_int32 ip_raw, subnet_mask_raw; //Raw ip and subnet mask
	struct in_addr address; // For converion from raw int ip to dotted ip
	char ip[13]; // IP
	char subnet_mask[13]; //Subnet mask
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

	// Conversion from raw to dotter network address

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

/*	pcap_freealldevs(interfaces);
	pcap = pcap_create(dev, errbuf);
	if(pcap_activate(pcap)!=0) {
		cerr<<"Failed to capture"<<endl;
		pcap_perror(pcap, errbuf);
		cerr<<errbuf<<endl;
		exit(-1);
	}
	cout<<"Running..."<<endl;*/

	
	return 0;
}
