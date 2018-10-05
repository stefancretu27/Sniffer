#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>

#include "sniffer.h"

//http://www.tcpdump.org/pcap.html
//http://www.tcpdump.org/manpages/pcap-filter.7.html
//https://www.devdungeon.com/content/using-libpcap-c

using namespace std;

//#define FILTER_TRAFFIC

/* 
 * Callback for pcap_loop() 
 * 
 * First argument is a u_char pointer to any user argument provided in pcap_loop()
 * Second argument is a ppinter to a struct containing metadata about the received packet, such as receiving time and packet's length
 * The third argument is a u_char pointer to the sniffed packet, which has to be typecasted to appropriate structures that model the headers of the target protocols
 */
void packet_handler_callback( u_char *args, const struct pcap_pkthdr* met_header, const u_char* packet) 
{
	static int packet_counter = 1;
	
	if(met_header == NULL)
	{
		cout<<"Packet's metadata header is null"<<endl;
		exit(EXIT_FAILURE);
	}
	
	if(packet == NULL)
	{
		cout<<"Received packet's content is null"<<endl;
		exit(EXIT_FAILURE); 
	}
	
	cout<<endl<<"Received packet with ID "<<packet_counter++<<" whose length is "<<met_header->len<<endl;
	
	/*
	 * Get Ethernet data
	 */ 
    struct ethernet_header *eth_header;
	//typecast packet u_char pointer to ethernet struct
    eth_header = (struct ethernet_header *) packet;
    
    cout<<"Ethernet type:";
    //ntohs: convert network byte order to host byte order
    switch(ntohs(eth_header->eth_type))
    {
		case ETHERTYPE_IP: 
			cout<<" IP"<<endl; 
			break;
		case ETHERTYPE_ARP:
			cout<<" ARP"<<endl; 
			break;
		case ETHERTYPE_REVARP:
			cout<<" REVARP"<<endl; 
			break;
		default:
			cout<<" not IP/ARP/REVARP"<<endl;
	}
	
	const char *aux = ether_ntoa(&eth_header->dest_addr);
	const char *dest_MAC = strcpy(new char[strlen(aux)+1], aux);
	cout<<"Dest MAC: "<<dest_MAC<<endl;
	aux = ether_ntoa(&eth_header->src_addr);
	const char *src_MAC = strcpy(new char[strlen(aux)+1], aux);
	cout<<"Source MAC: "<<src_MAC<<endl;
	
	/*
	 * Get IP data
	 */ 
	const struct ip_header *ip;
	u_int size_ip;
	
	//Since Ethernet header size is known, the IP header can be inferred by adding an offset to packet's pointer
	ip = (struct ip_header*)(packet + SIZE_ETHERNET);
	//IP header has 4-byte words
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) 
	{
		cout<<"IP header length is below 20"<<endl;
		exit(EXIT_FAILURE);
	}
	
	aux = inet_ntoa(ip->ip_dest);
	const char *dest_IP = strcpy(new char[strlen(aux)+1], aux);
	cout<<"Dest IP: "<<dest_IP<<endl;
	aux = inet_ntoa(ip->ip_src);
	const char *src_IP = strcpy(new char[strlen(aux)+1], aux);
	cout<<"Source IP: "<<src_IP<<endl;
	
	cout<<"IP protocol:";
	switch(ip->ip_protocol) 
	{
		case IPPROTO_TCP:
			cout<<" TCP"<<endl;
			break;
		case IPPROTO_UDP:
			cout<<" UDP"<<endl;
			break;
		case IPPROTO_ICMP:
			cout<<" ICMP"<<endl;
			break;
		case IPPROTO_IGMP:
			cout<<" IGMP"<<endl;
			break;
		case IPPROTO_IP:
			cout<<" IP"<<endl;
			break;
		default:
			cout<<ip->ip_protocol<<endl;
			break;
	}
	
	/*
	const struct sniff_tcp *tcp; 
	u_int size_tcp;
	
	//Once the IP header length is known, the TCP header can be inferred
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	//TCP header has 4-byte words
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) 
	{
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		exit(EXIT_FAILURE);
	}
	*/
}


int main()
{
	//pcap functions take as argument a char buffer to store the error code in 
	char errbuf[PCAP_ERRBUF_SIZE];
	const int sniffed_packets_no = 4;
	
	/*
	 * Step 1: determine on which interface is sniffed on
	 */  
	const char *device = "wlan0";
	/*pcap_lookupdev(errbuf);
	if (device == NULL) 
	{
		fprintf(stderr, "Couldn't find device to sniff on: %s\n", errbuf);
		exit(EXIT_FAILURE); 
	}
	*/
	
	//useful for Step 3
	bpf_u_int32 mask;
	bpf_u_int32 net_no;
	
	//get network number and net mask for the sniffing device
	if(pcap_lookupnet(device, &net_no, &mask, errbuf) == -1) 
	{
		fprintf(stderr, "Can't get netmask for device %s: %s\n", device, errbuf);
		net_no = 0;
		mask = 0;
	}

	/*
	 * Step 2: Set the sniffing session
	 * In general, it can be sniffed on multiple devices, for each one having a distinct session handler
	 *
	 * BUFSIZ = max number of sniffed bytes (defined in pcap header)
	 * 1 = turn the interface into promiscuous mode to sniff all traffic, not only the one related to host
	 * 1000 = sniffing time (miliseconds) 
	 */
	pcap_t *session_handler;
	
	session_handler = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
	if(session_handler == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
		exit(EXIT_FAILURE); 
	}
	
	cout<<"Opened sniffing session on device "<<device<<" with mask "<<mask<<" and network number "<<net_no<<endl;
	
	/*
	 * It has ot be determined the type of headers provided at link layer level.
	 * The type is used for packets' contents processing
	 * In this case it is checked for ethernet headers
	 */ 
	if(pcap_datalink(session_handler) != DLT_EN10MB) 
	{
		fprintf(stderr, "Device %s doesn't provide eth headers\n", device);
		exit(EXIT_FAILURE); 
	}
	
#ifdef FILTER_TRAFFIC
	/*
	 * Step 3 (sometimes optional)
	 * Settings for sniffing specific traffic, such as traffic on a given port
	 * 3 substeps: create a set of rules; compile it; apply it
	 */
	struct bpf_program bpf;
	/*
	 * Substep 3.1: Create rules
	 */ 
	const char* filter_expr = "ip"; 
	
	/*
	 * Substep 3.2: Compile the filtering rules
	 * 
	 * session_handler = the above set sniffing session
	 * bpf = struct containing the compiled version of the filter expr 
	 * filter_expr = string containing expresion to be compiled
	 * net_no = network number of sniffing device
	 */
	if(pcap_compile(session_handler, &bpf, filter_expr, 0, net_no) == -1) 
	{
		fprintf(stderr, "Filter %s coud not be compiled: %s\n", filter_expr, pcap_geterr(session_handler));
		exit(EXIT_FAILURE); 
	}
	
	/*
	 * Substep 3.3: Apply the compiled rules (bpf) to the opened session handler
	 */ 
	if(pcap_setfilter(session_handler, &bpf) == -1)
	{
		fprintf(stderr, "Filter %s could not be set: %s\n", filter_expr, pcap_geterr(session_handler));
		exit(EXIT_FAILURE); 
	}
#endif //FILTER_TRAFFIC

	/*
	 * Step 4: Sniffing
	 * Store length of the packet and the time it was sniffed in pcap_pkthdr struct
	 * Use pcap_next to get one packet. A unisgned char pointer to it is returned
	 */ 
	
	pcap_loop(session_handler, sniffed_packets_no, packet_handler_callback, NULL);
	
	/*
	 * Step 5: Sniffing done, close the session handler
	 */ 
#ifdef FILTER_TRAFFIC
	pcap_freecode(&bpf);
#endif //FILTER_TRAFFIC
	pcap_close(session_handler);
	
	return 0;
}
