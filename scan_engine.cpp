#ifndef SCAN_ENGINE_H
#include "scan_engine.h"
#endif

#ifndef WIN32
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
	is_opened = 1;
      }
    else
      {
	is_opened = 0;
      }
  close(sock);
  return is_opened;
}

inline int udp_scan(int port)
{
int is_opened = 1;
  char udp_data[] = "";
  char icmp_buffer[sizeof(struct icmp)+sizeof(struct iphdr)];
  struct sockaddr_in udp_addr;
  struct in_addr my_addr;
  struct icmp *icmp = (struct icmp *) (icmp_buffer + sizeof(struct ip));
  int sock, sock2;
struct timeval tv;
fd_set f;
int rv;
     if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0){
    perror("socket");
    exit(1);
  }
  if ((sock2 = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
  perror("socket");
  exit(1);
  }
  udp_addr.sin_family = AF_INET;
  udp_addr.sin_port = htons(port);
  udp_addr.sin_addr = *((struct in_addr *)host->h_addr);
  memset(&(udp_addr.sin_zero), '\0', 8);

    if (sendto(sock, udp_data, sizeof(udp_data), 0x0, (struct sockaddr *)&udp_addr, sizeof(udp_addr)) < 0)
      {
	perror("sendto");
	exit(1);
      }
close(sock);
tv.tv_sec = 0;
tv.tv_usec = 500;
FD_ZERO(&f);
FD_SET(sock2, &f);
rv = select((sock2 + 1), &f, NULL, NULL, &tv);
  if (rv)
  {
  if ((recvfrom(sock2, icmp_buffer, sizeof(icmp_buffer), 0x0, NULL, NULL)) < 0)
    {
    perror("recvfrom");
    exit(1);
    }
    if ((icmp->icmp_type == ICMP_UNREACH) && (icmp->icmp_code == ICMP_UNREACH_PORT))
    	{
	is_opened = 0;
	}
   }
close(sock2);
  return is_opened;
}

inline int raw_scan(int port, int scan_type)
{
  int is_opened = 0;
  int sock;
  int on=1;
  socklen_t ssize;
  int packet_size;
  packet_size = (sizeof(struct tcphdr)+sizeof(struct iphdr));
  char packet[packet_size];
  /* The headers */
  struct iphdr *iph = (struct iphdr  *)(packet);
  struct tcphdr *tcph = (struct tcphdr *)(packet+sizeof(struct iphdr));
  struct pseudohdr *pseudo = (struct pseudohdr *)(packet+sizeof(struct iphdr)+sizeof(struct tcphdr));
  struct in_addr saddr, daddr;
	struct sockaddr_in remote;

  if( (sock = socket( PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0 )
    { perror("socket"); exit(1); }


  if( (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on))) < 0 )
    { perror("setsockopt");  exit(1); }

  daddr = *((struct in_addr *)host->h_addr);
  /*set local IP*/
  saddr.s_addr = inet_addr(local_ip);
  /***********************/
  /* The pseudo header for the checksum */
  pseudo->saddr = saddr.s_addr;
  pseudo->daddr = daddr.s_addr;
  pseudo->protocol = IPPROTO_TCP;
  pseudo->zer0 = 0;
  pseudo->length = htons(sizeof(struct tcphdr));

  bzero( packet, packet_size );

  tcph->th_sport = htons(rand()%65535);
  tcph->th_dport   = htons(port);
  tcph->th_seq = htonl(random()%time(NULL));
  tcph->th_ack = 0;
  tcph->th_off = 5;

  tcph->th_flags = TH_SYN;
switch(scan_type)
	{
	case SYN:
  tcph->th_flags = TH_SYN;
	break;
	case FIN:
  tcph->th_flags = TH_FIN;
	break;
	case XMAS:
	tcph->th_flags = TH_FIN|TH_URG|TH_PUSH;
	break;
	case NULL_S:
	tcph->th_flags = 0;
	default:
	break;
	}
  tcph->th_win = htons(3072);
  tcph->th_sum = (unsigned short)in_cksum((unsigned short *)tcph, sizeof(struct tcphdr)+sizeof(struct pseudohdr));

  bzero(packet, sizeof(struct iphdr));

  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = htons(packet_size);
  iph->frag_off = 0;
  iph->ttl = IPDEFTTL;
  iph->protocol = IPPROTO_TCP;
  iph->check = (unsigned short)in_cksum((unsigned short *)iph, sizeof(struct iphdr));
  iph->saddr = saddr.s_addr;
  iph->daddr = daddr.s_addr;

  remote.sin_family = PF_INET;
  remote.sin_addr = daddr;
  remote.sin_port = htons(port);

  if( (sendto(sock, packet, sizeof(packet), 0x0, (struct sockaddr *)&remote, sizeof(remote))) < 0 )
   {  perror("sendto");  exit(1);  }
  bzero( packet, packet_size );
  close(sock);
  return is_opened;
}

/* The checksum function from the raw ip faq */
unsigned short in_cksum(unsigned short *addr,int len)
{
  register int sum = 0;
  u_short answer = 0;
  register u_short *w = addr;
  register int nleft = len;


  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1) {
    *(u_char *)(&answer) = *(u_char *)w ;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return(answer);
}

void get_ip()
{
  /*get_ip(), returns the local IP using /sbin/ifconfig which is reliable
    This is quite ugly and should be replaced by something better, that doesn't
    use pipes, or that depends on ppp0, eth0, or lo, device interfaces*/
  FILE *tmp;
  int x;
  if (gethostbyname("google.com") != NULL){
    tmp = popen("perl -e \"print readpipe('/sbin/ifconfig ppp0') =~ /inet\\ addr:(.*?) /;\"", "r");
    while (fgets(local_ip, sizeof(local_ip), tmp));
    if (strlen(local_ip) > 12) /*Try eth0 interface*/
      {
	tmp = popen("perl -e \"print readpipe('/sbin/ifconfig eth0') =~ /inet\\ addr:(.*?) /;\"", "r");
	while (fgets(local_ip, sizeof(local_ip), tmp))1;
      }
  }
  else{
    tmp = popen("perl -e \"print readpipe('/sbin/ifconfig lo') =~ /inet\\ addr:(.*?) /;\"", "r");
    while (fgets(local_ip, sizeof(local_ip), tmp))1;
  }
  fclose(tmp);
}

void set_sniffer(int scan_type)
{
int sockfd;
char buffer[(sizeof(struct tcphdr)+sizeof(struct iphdr))];
char udp_buffer[sizeof(struct icmp)+sizeof(struct iphdr)];
char udp_buffer2[sizeof(struct udphdr)+sizeof(struct iphdr)];
struct ip *ip = (struct ip *) buffer;
struct tcphdr *tcp;
struct icmp *icmp = (struct icmp *) (udp_buffer + sizeof(struct ip));
struct udphdr *udp = (struct udphdr *) (udp_buffer2 + sizeof(struct ip));
struct timeval tv;
struct sockaddr remote;
fd_set f;
int rv;
printf("starting sniffer\n");
if (scan_type != UDP)
{
if( (sockfd = socket( PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0 )
    { perror("socket"); exit(1); }
while(!STOP_SNIFFER)
	{
memset(buffer, 0, sizeof(buffer));
tv.tv_sec = 0;
tv.tv_usec = 500;
FD_ZERO(&f);
FD_SET(sockfd, &f);
rv = select((sockfd +1), &f, NULL, NULL, &timeout);
if (rv){
	if ((recvfrom(sockfd, buffer, sizeof(buffer), 0x0, NULL, NULL)) < 0)
			{
			perror("recvfrom");
			exit(1);
			}
tcp = (struct tcphdr *) (buffer + (ip->ip_hl << 2));
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
	}
}/*Scan type is UDP*/
else
{
  if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
    perror("socket");
    exit(1);
  }
while(!STOP_SNIFFER)
	{
	tv.tv_sec = 0;
tv.tv_usec = 500;
FD_ZERO(&f);
FD_SET(sockfd, &f);
rv = select((sockfd +1), &f, NULL, NULL, &timeout);
if (rv){
	if ((recvfrom(sockfd, udp_buffer, sizeof(udp_buffer), 0x0, NULL, NULL)) < 0){	perror("recvfrom");exit(1);	}
	if ((icmp->icmp_type == ICMP_UNREACH) && (icmp->icmp_code == ICMP_UNREACH_PORT))
		{
		 /*We know it's closed, and we can report it.  But how can we know which port?*/
		 //closed_raw_port(/*port goes here*/);
		}
}
	}
}
printf("stopping sniffer\n");
close(sockfd);
}
#endif

