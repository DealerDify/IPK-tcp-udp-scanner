#include <stdio.h>
#include <string.h>
#include <vector>
#include <regex>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h> //ifa_flags
#include <pcap/pcap.h>
#include <signal.h>
#include <unistd.h>
#include <sstream>

#define SOURCE_PORT 49152 //1st ephemeral port
#define TCP_PORT_EXPR_STR "tcp && dst port 49152"
#define TCP_PORT_EXPR_STR_pp "tcp && dst port 49153" //pokud se scanuje port 49152 je pouzit tento port
#define ETHERNET_SIZE 14 //ethernet size je vzdy 14 bytu

struct my_ip6
{
	uint8_t ver_traff; //vrchní4 bity = version = ipv6
	uint8_t traff_flow=0;
	uint8_t flow=0;
	uint16_t payload_len;
	uint8_t next_hdr; //next header version = tcp/udp
	uint8_t ttl; //hop limit = time to live
	uint8_t src_addr[16];//8*16=128
	uint8_t dst_addr[16];//8*16=128

};


struct pseudo_tcp_header
{
	u_int32_t src_adress;
	u_int32_t dest_adress;
	u_int8_t reserved_zeroes=0;
	u_int8_t protocol;
	u_int16_t len;
};

struct pseudo_tcp_header_ipv6
{
	in6_addr src_adress;
	in6_addr dest_adress;
	u_int32_t len;
	u_int16_t reserved_zeroes=0;
	u_int8_t reserved_zeroes2=0;
	u_int8_t protocol;
	
};

struct pseudo_udp_header_ipv6
{
	in6_addr src_adress;
	in6_addr dest_adress;
	u_int32_t len;
	u_int16_t reserved_zeroes=0;
	u_int8_t reserved_zeroes2=0;
	u_int8_t protocol;
};

pcap_t *handle;//pro pouziti pcap_breakloop po vyprseni casu alarmu

/*--------------------------------------------------------------------------------
 *From site: www.tenouk.com/Module43a.html
--------------------------------------------------------------------------------*/

#define PCKT_LEN 8192

// UDP header's structure
struct udpheader {
 u_int16_t udph_srcport;
 u_int16_t udph_destport;
 u_int16_t udph_len;
 u_int16_t udph_chksum;
};


// Function for checksum calculation. From the RFC,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
unsigned short csum(unsigned short *buf, int nwords)
{       //
        unsigned long sum;
        for(sum=0; nwords>0; nwords--)
                sum += *buf++;
        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);
        return (unsigned short)(~sum);
}
/*--------------------------------------------------------------------------------
 *End of part from www.tenouk.com
--------------------------------------------------------------------------------*/





std::vector<int> get_port_numbers_from_string(std::string given_ports)
{
	std::vector<int> ports_to_scan;
	std::regex valid_one_port("^(\\d+)$");
	std::regex valid_ports_comma("(\\d+)(?:,(\\d+))*");
	std::regex valid_ports_range("(\\d+)-(\\d+)");
	std::smatch match;

	if (std::regex_match(given_ports, valid_one_port))
	{
		ports_to_scan.push_back(std::stoi(given_ports));
	}
	else if (std::regex_match(given_ports, valid_ports_comma))
	{

/*--------------------------------------------------------------------------------
 *from site:http://www.martinbroadhurst.com/how-to-split-a-string-in-c.html
--------------------------------------------------------------------------------*/
		std::stringstream given_ports_stream(given_ports);
		std::string item;
		while(std::getline(given_ports_stream,item,','))
		{
			int port = std::stoi(item);
			if (port > 65535)
			{	
				fprintf(stderr, "Port ouf of range 0-65535\n");
				exit(-1);
			}
			ports_to_scan.push_back(port);
		}

/*-------------------end of code from: http://www.martinbroadhurst.com -------------------*/
	}
	else if (std::regex_match(given_ports, match, valid_ports_range))
	{
		int first_port = std::stoi(match[1].str());
		int last_port = std::stoi(match[2].str());
		if (last_port > 65535)
		{
			fprintf(stderr, "Port ouf of range 0-65535\n");
			exit(-1);
		}
		for (int i = first_port; i <= last_port; i++)
		{
			ports_to_scan.push_back(i);
		}
	}
	else
	{
		fprintf(stderr, "Invalid ports argument\n");
		exit(-1);
	}
	return ports_to_scan;
}

/*--------------------------------------------------------------------------------
 *Funkce inspirovana funkci na strance https://www.tcpdump.org/pcap.html
--------------------------------------------------------------------------------*/
void TCP_Packet_Handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ip *ip_head = (struct ip *)(packet + ETHERNET_SIZE);//ip header je az za ether header
	u_int size_of_ip = ip_head->ip_hl*4;
	struct tcphdr *tcp_head=(struct tcphdr *) (packet + ETHERNET_SIZE +size_of_ip);//tcp header je za ip header

	if(tcp_head->th_flags & TH_RST)
	{
		printf("Closed\n");
	}
	else
	{
		printf("Open\n");
	}
}

/*--------------------------------------------------------------------------------
 *Funkce inspirovana funkci na strance https://www.tcpdump.org/pcap.html
--------------------------------------------------------------------------------*/
void TCP_Packet_Handler_ipv6(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct my_ip6 *ip_head = (struct my_ip6 *)(packet + ETHERNET_SIZE);//ip header je az za ether header
	struct tcphdr *tcp_head=(struct tcphdr *) (packet + ETHERNET_SIZE + sizeof(struct my_ip6));//tcp header je za ip header

	if(tcp_head->th_flags & TH_RST)
	{
		printf("Closed\n");
	}
	else
	{
		printf("Open\n");
	}
}

void UDP_Packet_Handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	//pokud prijde odpoved je vzdy closed jinak neodpovi
	printf("Closed\n");
}

/*
 *function and setup further in code
 *inspired from site: https://stackoverflow.com/questions/4583386/listening-using-pcap-with-timeout
 *question from: https://stackoverflow.com/users/314336/xyzt
 *answer from: https://stackoverflow.com/users/1883178/lemonsqueeze
 *edited by: https://stackoverflow.com/users/1271826/rob
 */
void alarm_handler(int sig)
{
    pcap_breakloop(handle);
}

void fill_tcp(struct tcphdr *tcp,int dest_port,int src_port)
{
	tcp->th_dport=htons(dest_port);
	tcp->th_sport=htons(src_port);
	tcp->th_seq=htonl(1);
	tcp->th_ack=0;
	tcp->th_off=5;
	tcp->th_flags=TH_SYN;
	tcp->th_win=htons(65535);
	tcp->th_urp=0;
	tcp->th_sum=0;
	//chsum potreba doplnit mimo fci
}

void fill_udp(struct udpheader *udp,int dest_port)
{
	udp->udph_srcport=htons(SOURCE_PORT);
	udp->udph_destport=htons(dest_port);
	udp->udph_len=htons(sizeof(struct udpheader));
	udp->udph_chksum=0;
	//chcksum je potreba doplnit u ipv6 mimo fci u ipv4 je nepovinny
}

void fill_ip_tcp_ipv4(struct ip *ip_header,struct sockaddr_in *source_addr,struct sockaddr_in *dest_addr)
{
	ip_header->ip_src.s_addr=inet_addr(inet_ntoa(source_addr->sin_addr));
	ip_header->ip_dst.s_addr=inet_addr(inet_ntoa(dest_addr->sin_addr));
	ip_header->ip_hl=5;
	ip_header->ip_v=4;//ipv4
	ip_header->ip_tos=0;
	ip_header->ip_len=sizeof(struct ip) + sizeof(struct tcphdr);
	ip_header->ip_id=htons(54321);
	ip_header->ip_ttl=64;//time to live
	ip_header->ip_p=IPPROTO_TCP;
	ip_header->ip_off=0;
	//chsum potreba doplnit mimo fci
}

void fill_ip_tcp_ipv6(struct my_ip6 *ip_header,struct sockaddr_in6 *source_addr,struct sockaddr_in6 *dest_addr)
{
	ip_header->ver_traff=96; //ipv6 = 6*16
	ip_header->traff_flow=0;
	ip_header->flow=0;
	ip_header->payload_len=htons(sizeof(struct tcphdr));
	ip_header->ttl=64;//hops
	ip_header->next_hdr=IPPROTO_TCP;
	char str[INET6_ADDRSTRLEN];
	memset(str,0,INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6,&(((struct sockaddr_in6 *)source_addr)->sin6_addr),str,INET6_ADDRSTRLEN);
	inet_pton(AF_INET6,str,ip_header->src_addr);
	memset(str,0,INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6,&(((struct sockaddr_in6 *)dest_addr)->sin6_addr),str,INET6_ADDRSTRLEN);
	inet_pton(AF_INET6,str,ip_header->dst_addr);
}

void fill_ip_udp_ipv4(struct ip *ip_header,struct sockaddr_in *source_addr,struct sockaddr_in *dest_addr)
{
	ip_header->ip_src.s_addr=inet_addr(inet_ntoa(source_addr->sin_addr));
	ip_header->ip_dst.s_addr=inet_addr(inet_ntoa(dest_addr->sin_addr));
	ip_header->ip_hl=5;
	ip_header->ip_v=4;//ipv4
	ip_header->ip_tos=16;
	ip_header->ip_len=htons(sizeof(struct udpheader));
	ip_header->ip_id=htons(54321);
	ip_header->ip_ttl=64;//time to live
	ip_header->ip_p=IPPROTO_UDP;
	ip_header->ip_off=0;
	//chsum potreba doplnit mimo fci
}
void fill_ip_udp_ipv6(struct my_ip6 *ip_header,struct sockaddr_in6 *source_addr,struct sockaddr_in6 *dest_addr)
{
	ip_header->ver_traff=96; //ipv6 = 6*16
	ip_header->traff_flow=0;
	ip_header->flow=0;
	ip_header->payload_len=htons(sizeof(struct udpheader));
	ip_header->ttl=64;
	ip_header->next_hdr=IPPROTO_UDP;
	char str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6,&(((struct sockaddr_in6 *)source_addr)->sin6_addr),str,INET6_ADDRSTRLEN);
	inet_pton(AF_INET6,str,ip_header->src_addr);
	inet_ntop(AF_INET6,&(((struct sockaddr_in6 *)dest_addr)->sin6_addr),str,INET6_ADDRSTRLEN);
	inet_pton(AF_INET6,str,ip_header->dst_addr);
}

int main(int argc, char **argv)
{
//---------------------------------------ARGUMENTS PARSE-----------------------------------------
	std::vector<std::string> arguments(argv, argv + argc);
	std::string given_ports_udp;
	std::string given_ports_tcp;
	std::string given_interface;
	std::string given_ip_to_scan;
	bool got_pu=false;
	bool got_pt=false;
	bool got_ip=false;
	bool got_interface=false;
	for (std::size_t i=1; i < arguments.size() ; i+=2)
	{
		if (arguments[i] == "-pu")
		{
			if(got_pu)
			{
				fprintf(stderr, "Opakovane zadane -pu\n");
				exit(-1);
			}
			got_pu=true;
			if ((i + 1) < arguments.size())
			{
				given_ports_udp = arguments[i + 1];
			}
			else
			{
				fprintf(stderr, "Chybi specifikace -pu portu\n");
				exit(-1);
			}
		}
		else if (arguments[i] == "-pt")
		{
			if(got_pt)
			{
				fprintf(stderr, "Opakovane zadane -pt\n");
				exit(-1);
			}
			got_pt=true;
			if ((i + 1) < arguments.size())
			{
				given_ports_tcp = arguments[i + 1];
			}
			else
			{
				fprintf(stderr, "Chybi specifikace -pt portu\n");
				exit(-1);
			}
		}
		else if (arguments[i] == "-i")
		{
			if(got_interface)
			{
				fprintf(stderr, "Opakovane zadane -i\n");
				exit(-1);
			}
			if ((i + 1) < arguments.size())
			{
				given_interface = arguments[i + 1];
				got_interface=true;
			}
			else
			{
				fprintf(stderr, "Chybi specifikace interface u -i\n");
				exit(-1);
			}
		}
		else
		{
			if(got_ip)
			{
				fprintf(stderr, "Opakovane zadana ip/domain name nebo neznamy argument\n");
				exit(-1);
			}
			got_ip=true;
			given_ip_to_scan = arguments[i];
			i--;
		}
	}

	if (!(got_pt || got_pu))
	{
		fprintf(stderr, "Alespon jeden z -pu nebo -pt je povinny\n");
		exit(-1);
	}
	std::vector<int> udp_ports_to_scan;
	std::vector<int> tcp_ports_to_scan;
	if(got_pu)
	{
		udp_ports_to_scan = get_port_numbers_from_string(given_ports_udp);
		fprintf(stdout, "ports_scan_udp: %s\n", given_ports_udp.c_str());
	}
	if(got_pt)
	{
		tcp_ports_to_scan = get_port_numbers_from_string(given_ports_tcp);
		fprintf(stdout, "ports_scan_tcp: %s\n", given_ports_tcp.c_str());
	}
		

/*--------------------------------------------------------------------------------
 *Z manualovyh stranek getaddrinfo
--------------------------------------------------------------------------------*/
    struct addrinfo hints;
    struct addrinfo *result;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */

    if (getaddrinfo(given_ip_to_scan.c_str(),NULL , &hints, &result) != 0)
	{
		fprintf(stderr, "Invalid ip address or domain name\n");
        exit(-1);
	}
    struct sockaddr *addr = result->ai_addr;

    if(addr->sa_family==AF_INET)
    {
        printf("Domain/ip with ipv4: %s resolved: %s\n", given_ip_to_scan.c_str(),inet_ntoa(((struct sockaddr_in *)addr)->sin_addr));
    }
    else if(addr->sa_family==AF_INET6)
    {
        char str[INET6_ADDRSTRLEN];
        printf("Domain/ip with ipv6: %s resolved: %s\n", given_ip_to_scan.c_str(),inet_ntop(addr->sa_family,&(((struct sockaddr_in6 *)addr)->sin6_addr),str,INET6_ADDRSTRLEN));
    }
    else
    {
        fprintf(stderr, "Invalid ip address or domain name\n");
        exit(-1);
    }

    //-------------Get IP from interface---------------
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *tmp_addr = NULL;
    if(getifaddrs(&interfaces)==0)
    {
		tmp_addr = interfaces;
		if(got_interface)//pokud je interface specifikovany v argumentech
		{
			while (tmp_addr)
			{
				if(strcmp(tmp_addr->ifa_name,given_interface.c_str())==0 && tmp_addr->ifa_addr->sa_family==addr->sa_family)
				{//pokud je zadany interface shodny s nalezenym a ma spravnou IP adresu ipv4 nebo ipv6
					if(!(tmp_addr->ifa_flags & IFF_RUNNING))
						tmp_addr=NULL;//interface zadany argumentem neni aktivni
					else
						break;//zadany port je v poradku
				}
				tmp_addr=tmp_addr->ifa_next;
			}
		}
		else
		{
			while (tmp_addr)
			{
				if(tmp_addr->ifa_flags & IFF_LOOPBACK)
				{
					tmp_addr=tmp_addr->ifa_next;
					continue;
				}
				else if(!(tmp_addr->ifa_flags & IFF_RUNNING))
				{
					tmp_addr=tmp_addr->ifa_next;
					continue;
				}
				else if(tmp_addr->ifa_addr)
				{
					if(tmp_addr->ifa_addr->sa_family==addr->sa_family)
					{
						break;//tmp_addr je prvni neloopback interface se shodnou verzi ip jako zadana
					}
					else
					{
						tmp_addr=tmp_addr->ifa_next;
					}
				}
				else
				{
					tmp_addr=tmp_addr->ifa_next;
				}
			}
		}
    }//getifaddrs
	else
	{
		fprintf(stderr, "Could not get interfaces of machine\n");
        exit(-1);
	}

	if(tmp_addr==NULL)
	{
		fprintf(stderr,"Could not get local specified interface or non-specified nonloopback interface\n");
		exit(-1);
	}
	else
		printf("Interface name: %s\n",tmp_addr->ifa_name);


	if(addr->sa_family==AF_INET)
	{
//--------------------------------------------FOR TCP--------------------------------------------
		if(got_pt) for(int dest_port : tcp_ports_to_scan)
		{
			int source_port=SOURCE_PORT;
			if(dest_port==SOURCE_PORT)
			{//zajisteni aby fungoval filtr pro odeslane packety ze stejneho portu jako se scanuje
				source_port++;
			}

/*--------------------------------------------------------------------------------
 *From site: https://www.tenouk.com/Module43a.html
 *stranka byla jako doporucena literatura v zadani
--------------------------------------------------------------------------------*/  
			char buffer[PCKT_LEN];
			char pseudo_buffer[PCKT_LEN];
			// The size of the headers
			struct ip *ip_header = (struct ip *) buffer;
			struct tcphdr *tcp = (struct tcphdr *) (buffer + sizeof(struct ip));//realna tcp hlavicka
			struct tcphdr *tcp2 = (struct tcphdr *) (pseudo_buffer + sizeof(struct pseudo_tcp_header));
			//druha realna tcp hlavicka jinde v pameti pro vypocet chksum

			struct pseudo_tcp_header *pseudo_tcp = (struct pseudo_tcp_header *) pseudo_buffer;
			struct sockaddr_in *source_addr=(struct sockaddr_in *)tmp_addr->ifa_addr;
			struct sockaddr_in *dest_addr=(struct sockaddr_in *)addr;

			dest_addr->sin_port=dest_port;
			dest_addr->sin_family=AF_INET;

			source_addr->sin_port=source_port;
			source_addr->sin_family=AF_INET;

			int one = 1;
			const int *val = &one;
			memset(buffer, 0, PCKT_LEN);
			memset(pseudo_buffer, 0, PCKT_LEN);

			int sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
			if(sd < 0)
			{
				fprintf(stderr,"socket() error\n");
				exit(-1);
			}
/*--------------------------------------------------------------------------------
END OF code from site: www.tenouk.com
--------------------------------------------------------------------------------*/ 

			pseudo_tcp->src_adress=inet_addr(inet_ntoa(source_addr->sin_addr));
			pseudo_tcp->dest_adress=inet_addr(inet_ntoa(dest_addr->sin_addr));
			pseudo_tcp->protocol=IPPROTO_TCP;
			pseudo_tcp->len=htons(sizeof(struct tcphdr));

			fill_tcp(tcp,dest_port,source_port);
			*tcp2=*tcp;//kopie realne hlavicky do hlavicky v pseudo_bufferu
			tcp->th_sum=csum((unsigned short *)pseudo_buffer,sizeof(struct pseudo_tcp_header)+sizeof(struct tcphdr));

			fill_ip_tcp_ipv4(ip_header,source_addr,dest_addr);
			ip_header->ip_sum=csum((unsigned short *)buffer,sizeof(struct ip)+sizeof(struct tcphdr));
			
			if(setsockopt(sd,IPPROTO_IP,IP_HDRINCL,val,sizeof(one)) < 0)
			{
				fprintf(stderr,"setsockopt() error\n");
				exit(-1);
			}
			
			char errbuf[PCAP_ERRBUF_SIZE];

			handle = pcap_open_live(tmp_addr->ifa_name,BUFSIZ,1,1000,errbuf);
			if(handle==NULL)
			{
				fprintf(stderr,"pcap_open_live() error\n");
				exit(-1);
			}

			struct bpf_program fp; //compiled filter expression

			std::string filter_string_expr;
			if(source_port==49152)
				filter_string_expr.append(TCP_PORT_EXPR_STR);
			else
				filter_string_expr.append(TCP_PORT_EXPR_STR_pp);
			
			filter_string_expr.append(" && src port ");
			filter_string_expr.append(std::to_string(dest_port));

			pcap_compile(handle,&fp,filter_string_expr.c_str(),0,PCAP_NETMASK_UNKNOWN);
			pcap_setfilter(handle,&fp);

			if(sendto(sd,buffer,sizeof(struct ip)+sizeof(struct tcphdr),0,(struct sockaddr *)dest_addr,sizeof(struct sockaddr_in)) < 0)
			{
				fprintf(stderr,"sendto() error errno:%i\n%s\n",errno,strerror(errno));
				exit(-1);
			}

			alarm(3);//timeout for tcp bohuzel timeout pri pcap_open_live nefunguje
			signal(SIGALRM, alarm_handler);

			printf("TCP port:%i ",dest_port);
			int pcap_return = pcap_dispatch(handle,1,TCP_Packet_Handler,NULL);
			if(pcap_return <= 0)
			{
				//pokus zaslani druheho packetu
				if(sendto(sd,buffer,sizeof(struct ip)+sizeof(struct tcphdr),0,(struct sockaddr *)dest_addr,sizeof(struct sockaddr)) < 0)
				{
					fprintf(stderr,"sendto() error errno:%i\n%s\n",errno,strerror(errno));
					exit(-1);
				}
				
				alarm(3);//timeout pro tcp
				signal(SIGALRM, alarm_handler);
				pcap_return = pcap_dispatch(handle,1,TCP_Packet_Handler,NULL);
				if(pcap_return <= 0)
				{
					printf("Filtered\n");
				}
			
			}
			pcap_close(handle);
		}//for port in tcp_vector
		

//--------------------------------------------FOR UDP--------------------------------------------

		if(got_pu) for(int dest_port : udp_ports_to_scan)
		{
/*--------------------------------------------------------------------------------
 *From site: https://www.tenouk.com/Module43a.html
 *stranka byla jako doporucena literatura v zadani
--------------------------------------------------------------------------------*/ 
			char buffer[PCKT_LEN];

			struct ip *ip_header = (struct ip *) buffer;
			struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ip));//realna udp hlavicka

			struct sockaddr_in *source_addr=(struct sockaddr_in *)tmp_addr->ifa_addr;
			struct sockaddr_in *dest_addr=(struct sockaddr_in *)addr;
			dest_addr->sin_port=dest_port;
			dest_addr->sin_family=AF_INET;

			source_addr->sin_port=SOURCE_PORT;
			source_addr->sin_family=AF_INET;

			int one = 1;
			const int *val = &one;
			memset(buffer, 0, PCKT_LEN);

			int sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
			if(sd < 0)
			{
				fprintf(stderr,"socket() error\n");
				exit(-1);
			}
/*--------------------------------------------------------------------------------
 *END OF code from site: www.tenouk.com
--------------------------------------------------------------------------------*/


			fill_udp(udp,dest_port);
			fill_ip_udp_ipv4(ip_header,source_addr,dest_addr);
			ip_header->ip_sum=csum((unsigned short *)buffer,sizeof(struct ip)+sizeof(struct udpheader));
			
			if(setsockopt(sd,IPPROTO_IP,IP_HDRINCL,val,sizeof(one)) < 0)
			{
				fprintf(stderr,"setsockopt() error\n");
				exit(-1);
			}
			
			char errbuf[PCAP_ERRBUF_SIZE];

			handle = pcap_open_live(tmp_addr->ifa_name,BUFSIZ,1,1000,errbuf);
			if(handle==NULL)
			{
				fprintf(stderr,"pcap_open_live() error\n");
				exit(-1);
			}

			struct bpf_program fp; //compiled filter expression


			pcap_compile(handle,&fp,"icmp && icmp[icmptype] == icmp-unreach",0,PCAP_NETMASK_UNKNOWN);
			pcap_setfilter(handle,&fp);

			if(sendto(sd,buffer,sizeof(struct ip)+sizeof(struct udpheader),0,(struct sockaddr *)dest_addr,sizeof(struct sockaddr_in)) < 0)
			{
				fprintf(stderr,"sendto() error errno:%i\n%s\n",errno,strerror(errno));
				exit(-1);
			}

			alarm(3);//timeout for udp
			signal(SIGALRM, alarm_handler);

			printf("UDP port:%i ",dest_port);
			int pcap_return = pcap_dispatch(handle,1,UDP_Packet_Handler,NULL);
			if(pcap_return <= 0)
			{
				printf("Open\n");
			}
			pcap_close(handle);
		}

	}
	else if(addr->sa_family==AF_INET6)
	{
//--------------------------------------------FOR TCP--------------------------------------------
		if(got_pt) for(int dest_port : tcp_ports_to_scan)
		{
			int source_port=SOURCE_PORT;
			if(dest_port==SOURCE_PORT)
			{//zajisteni aby fungoval filtr pro odeslane packety ze stejnho portu jako se scanuje
				source_port++;
			}

/*--------------------------------------------------------------------------------
 *From site: https://www.tenouk.com/Module43a.html
 *stranka byla jako doporucena literatura v zadani
 *kod byl upraven pro ipv6
 --------------------------------------------------------------------------------*/

			char buffer[PCKT_LEN];
			char pseudo_buffer[PCKT_LEN];

			struct my_ip6 *ip_header = (struct my_ip6 *) buffer;
			struct tcphdr *tcp = (struct tcphdr *) (buffer + sizeof(struct my_ip6));//realna tcp hlavicka
			struct tcphdr *tcp2 = (struct tcphdr *) (pseudo_buffer + sizeof(struct pseudo_tcp_header_ipv6));
			//druha realna tcp hlavicka jinde v pameti pro vypocet chksum

			struct pseudo_tcp_header_ipv6 *pseudo_tcp = (struct pseudo_tcp_header_ipv6 *) pseudo_buffer;
			struct sockaddr_in6 *source_addr=(struct sockaddr_in6 *)tmp_addr->ifa_addr;
			struct sockaddr_in6 *dest_addr=(struct sockaddr_in6 *)addr;
			dest_addr->sin6_port=0;
			dest_addr->sin6_family=AF_INET6;

			source_addr->sin6_port=source_port;
			source_addr->sin6_family=AF_INET6;

			int one = 1;
			const int *val = &one;
			memset(buffer, 0, PCKT_LEN);
			memset(pseudo_buffer, 0, PCKT_LEN);

			int sd = socket(PF_INET6, SOCK_RAW, IPPROTO_TCP);
			if(sd < 0)
			{
				fprintf(stderr,"socket() error\n");
				exit(-1);
			}
/*--------------------------------------------------------------------------------
 *END OF code from site: www.tenouk.com
--------------------------------------------------------------------------------*/
			char str[INET6_ADDRSTRLEN];
			memset(str,0,INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6,&(((struct sockaddr_in6 *)source_addr)->sin6_addr),str,INET6_ADDRSTRLEN);
			inet_pton(AF_INET6,str,&pseudo_tcp->src_adress);

			memset(str,0,INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6,&(((struct sockaddr_in6 *)dest_addr)->sin6_addr),str,INET6_ADDRSTRLEN);
			inet_pton(AF_INET6,str,&(pseudo_tcp->dest_adress));

			pseudo_tcp->protocol=IPPROTO_TCP;
			pseudo_tcp->len=htonl(sizeof(struct tcphdr));

			fill_tcp(tcp,dest_port,source_port);
			*tcp2=*tcp;//kopie realne hlavicky do hlavicky v pseudo_bufferu
			tcp->th_sum=csum((unsigned short *)pseudo_buffer,sizeof(struct pseudo_tcp_header_ipv6)+sizeof(struct tcphdr));

			fill_ip_tcp_ipv6(ip_header,source_addr,dest_addr);

			if(setsockopt(sd,IPPROTO_IPV6,IPV6_HDRINCL,val,sizeof(one)) < 0)
			{
				fprintf(stderr,"setsockopt() error\n");
				exit(-1);
			}

			
			char errbuf[PCAP_ERRBUF_SIZE];

			handle = pcap_open_live(tmp_addr->ifa_name,BUFSIZ,1,1000,errbuf);
			if(handle==NULL)
			{
				fprintf(stderr,"pcap_open_live() error\n");
				exit(-1);
			}

			struct bpf_program fp; //compiled filter expression

			std::string filter_string_expr;
			if(source_port==49152)
				filter_string_expr.append(TCP_PORT_EXPR_STR);
			else
				filter_string_expr.append(TCP_PORT_EXPR_STR_pp);
			filter_string_expr.append(" && src port ");
			filter_string_expr.append(std::to_string(dest_port));

			pcap_compile(handle,&fp,filter_string_expr.c_str(),0,PCAP_NETMASK_UNKNOWN);
			pcap_setfilter(handle,&fp);

			memset(str,0,INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6,&(((struct sockaddr_in6 *)source_addr)->sin6_addr),str,INET6_ADDRSTRLEN);

			memset(str,0,INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6,&dest_addr->sin6_addr,str,INET6_ADDRSTRLEN);

			if(sendto(sd,buffer,sizeof(struct my_ip6)+sizeof(struct tcphdr),0,(struct sockaddr *)dest_addr,sizeof(struct sockaddr_in6)) < 0)
			{
				fprintf(stderr,"sendto() error errno:%i\n%s\n",errno,strerror(errno));
				exit(-1);
			}

			alarm(3);//timeout pro tcp bohuzel timeout pri pcap_open_live nefunguje
			signal(SIGALRM, alarm_handler);

			printf("TCP port:%i ",dest_port);
			int pcap_return = pcap_dispatch(handle,1,TCP_Packet_Handler_ipv6,NULL);
			if(pcap_return <= 0)
			{
				//pokus zaslani druheho packetu
				dest_addr->sin6_port=0;
				if(sendto(sd,buffer,sizeof(struct my_ip6)+sizeof(struct tcphdr),0,(struct sockaddr *)dest_addr,sizeof(struct sockaddr_in6)) < 0)
				{
					fprintf(stderr,"sendto() error errno:%i\n%s\n",errno,strerror(errno));
					exit(-1);
				}
				
				alarm(3);//timeout pro tcp
				signal(SIGALRM, alarm_handler);
				pcap_return = pcap_dispatch(handle,1,TCP_Packet_Handler_ipv6,NULL);
				if(pcap_return <= 0)
				{
					printf("Filtered\n");
				}
			
			}
			pcap_close(handle);
		}//for port in tcp_vector (ipv6)
		
//--------------------------------------------FOR UDP--------------------------------------------
		if(got_pu) for(int dest_port : udp_ports_to_scan)
		{
/*--------------------------------------------------------------------------------
 *From site: https://www.tenouk.com/Module43a.html
 *stranka byla jako doporucena literatura v zadani
 *kod byl upraven pro ipv6
--------------------------------------------------------------------------------*/ 
			
			char buffer[PCKT_LEN];
			char pseudo_buffer[PCKT_LEN];
			// The size of the headers
			struct my_ip6 *ip_header = (struct my_ip6 *) buffer;
			struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct my_ip6));//realna udp hlavicka
			struct udpheader *udp2 = (struct udpheader *) (pseudo_buffer + sizeof(struct pseudo_udp_header_ipv6));
			//druha realna udp hlavicka jinde v pameti pro vypocet chksum

			//struct pseudo_udp_header *pseudo_udp = (struct pseudo_udp_header *) pseudo_buffer;
			struct pseudo_udp_header_ipv6 *pseudo_udp = (struct pseudo_udp_header_ipv6 *) pseudo_buffer;
			struct sockaddr_in6 *source_addr=(struct sockaddr_in6 *)tmp_addr->ifa_addr;
			struct sockaddr_in6 *dest_addr=(struct sockaddr_in6 *)addr;
			dest_addr->sin6_port=0;
			dest_addr->sin6_family=AF_INET6;

			source_addr->sin6_port=SOURCE_PORT;
			source_addr->sin6_family=AF_INET6;

			int one = 1;
			const int *val = &one;
			memset(buffer, 0, PCKT_LEN);
			memset(pseudo_buffer, 0, PCKT_LEN);

			int sd = socket(PF_INET6, SOCK_RAW, IPPROTO_UDP);
			if(sd < 0)
			{
				fprintf(stderr,"socket() error\n");
				exit(-1);
			}

/*--------------------------------------------------------------------------------
 *END OF code from site: www.tenouk.com
--------------------------------------------------------------------------------*/
			udp->udph_chksum=0;

			char str[INET6_ADDRSTRLEN];
			memset(str,0,INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6,&(((struct sockaddr_in6 *)source_addr)->sin6_addr),str,INET6_ADDRSTRLEN);
			inet_pton(AF_INET6,str,&pseudo_udp->src_adress);

			memset(str,0,INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6,&(((struct sockaddr_in6 *)dest_addr)->sin6_addr),str,INET6_ADDRSTRLEN);
			inet_pton(AF_INET6,str,&(pseudo_udp->dest_adress));

			pseudo_udp->protocol=IPPROTO_UDP;
			pseudo_udp->len=htonl(sizeof(struct udpheader));
			pseudo_udp->reserved_zeroes2=0;
			pseudo_udp->reserved_zeroes=0;

			fill_udp(udp,dest_port);
			*udp2=*udp;//kopie realne hlavicky do hlavicky v pseudo_bufferu

			udp->udph_chksum=csum((unsigned short *)pseudo_buffer,sizeof(struct pseudo_tcp_header_ipv6)+sizeof(struct udpheader));
			fill_ip_udp_ipv6(ip_header,source_addr,dest_addr);

			if(setsockopt(sd,IPPROTO_IPV6,IPV6_HDRINCL,val,sizeof(one)) < 0)
			{
				fprintf(stderr,"setsockopt() error\n");
				exit(-1);
			}
			
			char errbuf[PCAP_ERRBUF_SIZE];

			handle = pcap_open_live(tmp_addr->ifa_name,BUFSIZ,1,1000,errbuf);
			if(handle==NULL)
			{
				fprintf(stderr,"pcap_open_live() error\n");
				exit(-1);
			}

			struct bpf_program fp; //compiled filter expression

			pcap_compile(handle,&fp,"icmp6",0,PCAP_NETMASK_UNKNOWN);
			pcap_setfilter(handle,&fp);

			if(sendto(sd,buffer,sizeof(struct my_ip6)+sizeof(struct udpheader),0,(struct sockaddr *)dest_addr,sizeof(struct sockaddr_in6)) < 0)
			{
				fprintf(stderr,"sendto() error errno:%i\n%s\n",errno,strerror(errno));
				exit(-1);
			}

			alarm(3);//timeout for udp
			signal(SIGALRM, alarm_handler);

			printf("UDP port:%i ",dest_port);
			int pcap_return = pcap_dispatch(handle,1,UDP_Packet_Handler,NULL);
			if(pcap_return <= 0)
			{
				printf("Open\n");
			}
			pcap_close(handle);
		}
	}
	else
	{
		fprintf(stderr,"Unkown sa_family\n");
		exit(-1);	
	}
	
}