#ifndef SCAN_ENGINE_H
#include "scan_engine.h"
#endif

#define close closesocket

inline int udp_scan(int port)
{
int success = 0;
return success;
}

inline int tcp_scan(int port)
{
  int sock = 0;
  int is_opened = 0;
  struct sockaddr_in tcp_dest;
  int success = -1;
  if((sock = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
      printf("Couldn't make socket!\n");
      exit(-1);
    }

  tcp_dest.sin_family = AF_INET;
  tcp_dest.sin_port = htons(port);
  tcp_dest.sin_addr = *((struct in_addr *)host->h_addr);
  memset(&(tcp_dest.sin_zero), '\0', 8);

  success = connect(sock , (struct sockaddr *)&tcp_dest, sizeof(struct sockaddr));

    if (success != -1)
      {
	is_opened = TRUE;
      }
    else
      {
	is_opened = FALSE;
      }
  close(sock);
  return is_opened;
}

#if (defined WINSOCK1 && defined WIN32)
inline int raw_scan(int port, int scan_type)
{
printf("You cannot call this function\n");
return 0;
}
void set_sniffer(int scan_type)
{
printf("You cannot call this function\n");
}
#endif

#ifndef WINSOCK1
inline int raw_scan(int port, int scan_type)
{
int success = 0;
/*TODO*/

return success;
}

void set_sniffer(int scan_type)
{
int sock;
char temp[MAX_HOSTNAME_LAN];
char buffer[sizeof(struct iphdr) + sizeof(struct tcphdr)];
struct iphdr *ip = (struct iphdr *)(buffer + sizeof(iphdr));
struct tcphdr *tcp;
struct hostent *h;
DWORD dwBytesRet;
int optval = 1;
SOCKADDR_IN sa;
gethostname(temp, MAX_HOSTNAME_LAN);
h = gethostbyname(temp);
sa.sin_family = AF_INET;
sa.sin_port = htons(0);
memcpy(&sa.sin_addr.S_un.S_addr, h->h_addr_list[0], h->h_length);
sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
//setsockopt(sock,IPPROTO_TCP,IP_HDRINCL, (char*)&optval, sizeof(optval));
bind(sock, (SOCKADDR *)&sa, sizeof(sa));
WSAIoctl(sock, SIO_RCVALL, &optval, sizeof(optval), NULL, 0, &dwBytesRet, NULL, NULL);
printf("starting sniffer\n");
STARTED_SNIFFER = 1;
while(!STOP_SNIFFER)
    {
    memset(buffer, 0, sizeof(buffer));
	recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
	tcp = (struct tcphdr *)(buffer + (ip->tot_len << 2));
unsigned int x;
for (x = 0; x <= sizeof(buffer); x++)
printf("%x2", buffer[x]);

printf("\n\n");
if (scan_type == FIN || scan_type == XMAS || scan_type == NULL_S)
{
			if (tcp->th_flags & TH_RST)
			closed_raw_port(ntohs(tcp->th_sport));
}
if (scan_type == SYN)
{
		if (tcp->th_flags & TH_SYN){
		if (tcp->th_flags &TH_ACK){
		opened_raw_port(ntohs(tcp->th_sport));}}
}
    }
closesocket(sock);
STARTED_SNIFFER = 0;
}
#endif

void get_ip()
{
char temp[MAX_HOSTNAME_LAN];
struct hostent *h;
gethostname(temp, MAX_HOSTNAME_LAN);
h = gethostbyname(temp);
local_ip = inet_ntoa(*((struct in_addr *)h->h_addr));
}

USHORT in_cksum(USHORT *buffer, int size)
{
    unsigned long cksum=0;
    while (size > 1)
    {
        cksum += *buffer++;
        size  -= sizeof(USHORT);
    }
    if (size)
    {
        cksum += *(UCHAR*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (USHORT)(~cksum);
}


