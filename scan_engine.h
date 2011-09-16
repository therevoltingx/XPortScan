#define SCAN_ENGINE_H

#include <stdio.h>
#include <stdlib.h>

#include <string>

#ifdef WIN32
#include <windows.h>
#endif

#if (defined WINSOCK1 && defined WIN32)
#include <winsock.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifndef WIN32
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#define __FAVOR_BSD
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#endif

enum{
SYN,
FIN,
XMAS,
NULL_S,
UDP,
};

#ifdef WIN32
USHORT in_cksum(USHORT *buffer, int size);
#else
unsigned short in_cksum(unsigned short *addr,int len);
#endif
inline int tcp_scan(int port);
inline int udp_scan(int port);
inline int raw_scan(int port, int scan_type);

struct hostent *host;
struct timeval timeout;

#ifdef WIN32
char *local_ip;
#else
char local_ip[100];
#endif
int STOP_SNIFFER;
int STARTED_SNIFFER;

void closed_raw_port(int port);
void opened_raw_port(int port);


void get_ip();
void set_sniffer(int scan_type);

#define MAX_ADDR_LEN 16
#define MAX_HOSTNAME_LAN 255

#if (!defined WINSOCK1 && defined WIN32)
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)
#define IPDEFTTL 255
#define TH_CWR 0x80 // 10000000
#define TH_ECE 0x40 // 01000000
#define TH_URG 0x20 // 00100000
#define TH_ACK 0x10 // 00010000
#define TH_PUSH 0x08 // 00001000
#define TH_RST 0x04 // 00000100
#define TH_SYN 0x02 // 00000010
#define TH_FIN 0x01
#endif

/*headers*/
struct pseudohdr  {
  unsigned long saddr;
  unsigned long daddr;
  char zer0;
  unsigned char protocol;
  unsigned short length;
};
#ifdef WIN32
struct tcphdr {
 unsigned short int th_sport;
 unsigned short int th_dport;
 unsigned int th_seq;
 unsigned int th_ack;
 unsigned char th_x2:4, th_off:4;
 unsigned char th_flags;
 unsigned short int th_win;
 unsigned short int th_sum;
 unsigned short int th_urp;
};

struct iphdr {
 unsigned char ihl:4, version:4;
 unsigned char tos;
 unsigned short int tot_len;
 unsigned short int ip_id;
 unsigned short int frag_off;
 unsigned char ttl;
 unsigned char protocol;
 unsigned short int check;
 unsigned int saddr;
 unsigned int daddr;
};

struct udp_hdr
{
    unsigned short sport;
    unsigned short dport;
    unsigned short Length;
    unsigned short Checksum;
};
#endif

