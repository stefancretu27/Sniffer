#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>

#include <jsoncpp/json/json.h>
#include <jsoncpp/json/writer.h>
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
	
	//start writing data into json object
	Json::Value json_packet_data;
	json_packet_data["ID"] = packet_counter;
	json_packet_data["Packet's length"] = met_header->len;
	
	/*
	 * Get Ethernet data
	 */ 
    struct ethernet_header *eth_header;
	//typecast packet u_char pointer to ethernet struct
    eth_header = (struct ethernet_header *) packet;
    
    //ntohs: convert network byte order to host byte order
    switch(ntohs(eth_header->eth_type))
    {
		//macros define din netinet/ether.h
		case ETHERTYPE_IP: 
			json_packet_data["Ethernet"]["Type"] = "IP"; 
			break;
		case ETHERTYPE_ARP: 
			json_packet_data["Ethernet"]["Type"] = "ARP";
			break;
		case ETHERTYPE_REVARP:
			json_packet_data["Ethernet"]["Type"] = "REVARP"; 
			break;
		default:
			json_packet_data["Ethernet"]["Type"] = "not IP/ARP/REVARP";
	}
	
	
	//ether_ntoa returns a const char* (statical) which si overwritten by next ether_ntoa calls => copy the returned array into another memory address
	const char *aux = ether_ntoa(&eth_header->dest_addr);
	const char *dest_MAC = strcpy(new char[strlen(aux)+1], aux);
	json_packet_data["Ethernet"]["Destination MAC address"] = dest_MAC;
	
	aux = ether_ntoa(&eth_header->src_addr);
	const char *src_MAC = strcpy(new char[strlen(aux)+1], aux);
	json_packet_data["Ethernet"]["Source MAC address"] = src_MAC;
	
	/*
	 * Get IP data
	 */ 
	const struct ip_header *ip;
	unsigned short size_ip_header;
	
	//Since Ethernet header size is known, the IP header can be inferred by adding an offset to packet's pointer
	ip = (struct ip_header*)(packet + SIZE_ETHERNET);
	//IP header has 4-byte words, so compute its size and check it
	size_ip_header = IP_HL(ip)*4;
	if (size_ip_header < 20) 
	{
		cout<<"IP header length is below 20: "<<size_ip_header<<endl;
		exit(EXIT_FAILURE);
	}
	
	switch(ip->ip_protocol) 
	{
		//macros defined in netinet/in
		case IPPROTO_TCP:
			json_packet_data["IP"]["Protocol"] = "TCP";
			break;
		case IPPROTO_UDP:
			json_packet_data["IP"]["Protocol"] = "UDP";
			break;
		case IPPROTO_ICMP:
			json_packet_data["IP"]["Protocol"] = "ICMP";
			break;
		case IPPROTO_IGMP:
			json_packet_data["IP"]["Protocol"] = "IGMP";
			break;
		case IPPROTO_IP:
			json_packet_data["IP"]["Protocol"] = "IP";
			break;
		case IPPROTO_IPV6:
			json_packet_data["IP"]["Protocol"] = "IPv6";
			break;
		default:
			json_packet_data["IP"]["Protocol"] = ip->ip_protocol;
			break;
	}
	
	//inet_ntoa returns a const char* (statical) which si overwritten by next inet_ntoa calls => copy the returned array into another memory address
	aux = inet_ntoa(ip->ip_dest);
	const char *dest_IP = strcpy(new char[strlen(aux)+1], aux);
	json_packet_data["IP"]["Destination IP address"] = dest_IP;
	
	aux = inet_ntoa(ip->ip_src);
	const char *src_IP = strcpy(new char[strlen(aux)+1], aux);
	json_packet_data["IP"]["Source IP address"] = src_IP;
	
	struct hostent *he = gethostbyaddr( ((const char*)&ip->ip_dest), sizeof(struct in_addr), AF_INET);
	if(he == NULL)
	{
		cout<<"Couldn't get hostname"<<endl;
		exit(EXIT_FAILURE);
	}
	
	json_packet_data["IP"]["hostname"] = he->h_name;
	
	/*
	 * Get TCP data
	 */ 
	if(ip->ip_protocol == IPPROTO_TCP)
	{
		const struct tcp_header *tcp; 
		unsigned short size_tcp_header;
		
		//Once the IP header length is known, the TCP header can be inferred
		tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_ip_header);
		//TCP header has 4-byte words, so compute its offset and check its size
		size_tcp_header = TCP_OFF(tcp)*4;
		if (size_tcp_header < 20) 
		{
			cout<<"TCP header length is below 20: "<<size_tcp_header<<endl;
			exit(EXIT_FAILURE);
		}
		
		json_packet_data["TCP"]["Destination port"] = ntohs(tcp->tcp_dest_port);
		json_packet_data["TCP"]["Source port"] = ntohs(tcp->tcp_src_port);
		
		unsigned short tcp_flag = tcp->tcp_flags&TCP_FIN;
		json_packet_data["TCP"]["Flags"]["FIN"] = tcp_flag;
		
		tcp_flag = tcp->tcp_flags&TCP_SYN;
		json_packet_data["TCP"]["Flags"]["SYN"] = tcp_flag;
		
		tcp_flag = tcp->tcp_flags&TCP_RST;
		json_packet_data["TCP"]["Flags"]["RST"] = tcp_flag;
		
		tcp_flag = tcp->tcp_flags&TCP_PUSH;
		json_packet_data["TCP"]["Flags"]["PUSH"] = tcp_flag;
		
		tcp_flag = tcp->tcp_flags&TCP_ACK;
		json_packet_data["TCP"]["Flags"]["ACK"] = tcp_flag;
		
		tcp_flag = tcp->tcp_flags&TCP_URG;
		json_packet_data["TCP"]["Flags"]["URG"] = tcp_flag;
		
		tcp_flag = tcp->tcp_flags&TCP_ECE;
		json_packet_data["TCP"]["Flags"]["ECE"] = tcp_flag;
		
		tcp_flag = tcp->tcp_flags&TCP_CWR;
		json_packet_data["TCP"]["Flags"]["CWR"] = tcp_flag;
	}
	
	//write the json objhect into JSON file
	ofstream file_id;
    file_id.open("packet"+to_string(packet_counter++)+".json", ios::out);
    
	Json::StyledWriter styledWriter;
	file_id << styledWriter.write(json_packet_data);
	
	file_id.close();
}


int main()
{
	//pcap functions take as argument a char buffer to store the error code in 
	char errbuf[PCAP_ERRBUF_SIZE];
	const int sniffed_packets_no = 8;
	
	/*
	 * Step 1: determine on which interface is sniffed on
	 */  
	const char *device = "wlan0";
	/*const char *device = pcap_lookupdev(errbuf);
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
