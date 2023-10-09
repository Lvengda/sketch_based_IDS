#pragma once

#include "param.h"
//#include "LTC.h"

#pragma pack (1)

/* 4 bytes IP address */
struct ip_address {
	uint8_t byte1;
	uint8_t byte2;
	uint8_t byte3;
	uint8_t byte4;
};

struct ip_header {
	uint8_t	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	uint8_t	tos;			// Type of service 
	uint16_t tlen;			// Total length 
	uint16_t identification;// Identification
	uint16_t flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	uint8_t	ttl;			// Time to live
	uint8_t	proto;			// Protocol
	uint16_t crc;			// Header checksum
	ip_address saddr;		// Source address
	ip_address daddr;		// Destination address
	uint32_t op_pad;		// Option + Padding
};

struct udp_header {
	uint16_t sport;			// Source port
	uint16_t dport;			// Destination port
	uint16_t len;			// Datagram length
	uint16_t crc;			// Checksum
};

struct tcp_header {
	uint16_t sport;			// Source port			
	uint16_t dport;			// Destination port		
	uint32_t seq;			// Serial number		
	uint32_t ack;			// Ack number			
	uint16_t hl_re_iden;
	//u_short hl : 4;		// Header length		
	//u_short re : 6;		// Reserved bits		
	//u_short iden : 6;		// Identification			
	uint16_t win_size;		// Window size			
	uint16_t checksum;		// Checksum				
	uint16_t urg_pointer;	// Urgent pointer		
	uint32_t op_pad;		// Option + Padding		32bits*n
};


//extern pcap_t* adhandle;		// Handler of network adapter
//extern bool HANDLE_FLAG;		// Stop capturing if false
//extern bool Record;			// Record the id and IP info on the first run
//extern LTC ltc_sketch;		// Sketch

void read_label_file();
void run_offline(string input_pcap, int MEM, int d, int m, int k, int lower, int middle, int upper, int period, int seed, FILE* f_recall);
uint32_t get_flow_id(const u_char* pktdata, int seed, short* payload);
void sig_handler(int sig);		// Capture the Ctrl^C signal to stop capturing traffic
pcap_t* set_handler();			// Set network adapter handler
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);	// Call back function to process captured packets
unsigned __stdcall break_handler(void* param);		// Stop capturing