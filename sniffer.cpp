#include <iostream>
#include <string>
#include <cstdlib>
#include <cstdio>

//packet capture
extern "C"
{
	#include <pcap.h>
}

using namespace std;

int main()
{
	//pcap functions take as argument a char buffer to store the error code in
	char errbuf[PCAP_ERRBUF_SIZE];
	
	//device/interface that is sniffed for packet capturing. Hardcoded as my eth0 is not set, hence not used
	const char* device = "wlan0";

	/*
	 * Open the device/interface for sniffing
	 * BUFSIZ = max number of sniffed bytes (defined in pcap header)
	 * 1 = turn the interface into promiscuous mode to sniff all traffic, not only the one related to host
	 * 1000 = how long (time in miliseconds) is sniffed
	 */
	pcap_t *session_handler = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
	if (session_handler == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
		exit(EXIT_FAILURE); 
	}

	/*
	 * It has ot be determined the type of headers provided at link layer level.
	 * The type is sued for packets' contents processing
	 * In this case it is checked for ethernet headers
	 */ 
	if (pcap_datalink(session_handler) != DLT_EN10MB) 
	{
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", device);
		exit(EXIT_FAILURE); 
	}
	
	

	
	return 0;
}
