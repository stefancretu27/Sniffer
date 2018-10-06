#ifndef SNIFFER_H
#define SNIFFER_H

//packet capture
#include <pcap.h>

#include <netinet/in.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
//for gethostbyaddr
#include <netdb.h>


//Ethernet headers are always exactly 14 bytes 
#define SIZE_ETHERNET 14

// Ethernet header 
struct ethernet_header 
{
	//MAC addresses
	const struct ether_addr dest_addr;
	const struct ether_addr src_addr; 
	//protocol type: IP/ARP/REVARP
	u_short eth_type; 
};

// IP header 
struct ip_header 
{
	// version << 4 | header length >> 2 
	u_char ip_vhl;
	// type of service
	u_char ip_tos;
	//total length
	u_short ip_len;
	//identification
	u_short ip_id;
	//fragment offset 	
	u_short ip_off;		
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	//TTL - time to live
	u_char ip_ttl;		
	//protocol
	u_char ip_protocol;
	//checksum	
	u_short ip_checksum;		
	//source and destination IP addresses
	struct in_addr ip_src;
	struct in_addr ip_dest;
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

// TCP header 
typedef u_int tcp_seq;

struct tcp_header
{
	//source and destionation ports
	u_short tcp_src_port;	
	u_short tcp_dest_port;
	//sequence number	
	tcp_seq tcp_seq_no;	
	//acknowledgement number	
	tcp_seq tcp_ack_no;	
	//offset	
	u_char tcp_offx2;	
#define TCP_OFF(tcp_head)	(((tcp_head)->tcp_offx2 & 0xf0) >> 4)
	u_char tcp_flags;
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80
#define TCP_FLAGS (TCP_FIN|TCP_SYN|TCP_RST|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)
	//window
	u_short tcp_window;		
	//checksum
	u_short tcp_checksum;		
	//urgent pointer
	u_short tcp_urgent_pointer;		
};

#endif
