#ifndef SNIFFER_H
#define SNIFFER_H

//packet capture
#include <pcap.h>
//for struct in_addr
#include <netinet/in.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <arpa/inet.h>


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
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_protocol;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src;
	struct in_addr ip_dest; /* source and dest address */
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

// TCP header 
typedef u_int tcp_seq;

struct tcp_header
{
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

#endif
