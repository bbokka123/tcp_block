#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

uint16_t ip_checksum(uint8_t *buf, uint16_t len)
{
        uint32_t sum = 0;
	int i=0;

        while(len >1){
                sum += buf[i]<<8 | buf[i+1];
                i+=2;
                len-=2;
        }
        if (len){
                sum += buf[i]<<8 | 0x00;
        }
        while (sum>>16){
		sum = (sum + ( sum>>16 )) & 0xffff;
        }

        return( (uint16_t) sum ^ 0xFFFF);
}
void tcp_checksum(struct ip *iph, struct tcphdr *tcph) {
	uint16_t *p = (uint16_t *)tcph;
	uint16_t *tempip;
	uint16_t datalen = ntohs(iph->ip_len) - 20 ;
	uint16_t len = datalen;
	uint32_t chksum = 0;
	len >>= 1;
	tcph->th_sum = 0;
	for(int i =0; i<len;i++) {
		chksum += *p++;
	}

	if(datalen % 2 == 1) {
		chksum += *p++ & 0x00ff;
	}
	tempip = (uint16_t *)(&iph->ip_dst);
	for(int i=0;i<2;i++) {
		chksum += *tempip++;
	}
	tempip = (uint16_t *)(&iph->ip_src);
	for(int i=0;i<2;i++) {
		chksum += *tempip++;
	}
	chksum += htons(6);
	chksum += htons(datalen);
	chksum = (chksum >> 16) +(chksum & 0xffff);
	chksum += (chksum >> 16);
	tcph->th_sum = (~chksum & 0xffff);
}	 
int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
  
  char* dev = argv[1];  //옵션 1: 네트웍 디바이스 이름을 인자로 넘겨준다.
  //char *dev=pcap_lookupdev(errbuf); //옵션 2:사용중인 네트웍 디바이스 이름을 얻어온다.
  char errbuf[PCAP_ERRBUF_SIZE];
  
  u_int8_t tmp[6];
  struct  in_addr tmp_ip;
  u_int16_t tmp_port;
  u_int32_t tmp_syn;
  
  int Datalen = 0 ;


  if(dev == NULL){
	  printf("%s\n", errbuf);
	  exit(1);
  }
  // 네트웍 디바이스 이름 출력
  printf("DEV: %s\n",dev);

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
  //descriptor를 생성한다. 3 번째 인자 1은 promiscuous mode로 로컬네트웍의
  //모든 패킷을 캡처한다. 
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  while (1) {
    struct pcap_pkthdr* header;
    const u_char *packet;
    int res = pcap_next_ex(handle, &header, &packet);
    u_char* packetdata;
    
    //header packet값을 통해 패킷 정보를 얻어온다.
    if(res==0) continue;
    if(res == -1 || res == -2) break;
    printf("%u bytes captured\n",header->caplen);
    
    int count =1 ;
    int length= header ->caplen;
    struct ether_header *ethh;
    uint16_t ether_type;   
    ethh = (struct ether_header *)packet;
    printf("Src ether addr:");
    for(int i=0; i<5;i++){
    printf("%02x:",ethh->ether_shost[i]);
    }	
    printf("%02x\n",ethh->ether_shost[5]);
    printf("Dst ether addr:");
    for(int i=0; i<5; i++){
    printf("%02x:",ethh->ether_dhost[i]);
    }
    printf("%02x\n",ethh->ether_dhost[5]);

    packet += sizeof(struct ether_header);
    
    ether_type = ntohs(ethh->ether_type);
    
    
    if(ether_type == ETHERTYPE_IP)
    {
	    struct ip *iph;
	    iph=(struct ip *)packet;
	    int ip_size= 4*(iph->ip_hl); 
	    printf("<IP information>\n");
	    printf("Src IP addr: %s\n", inet_ntoa(iph->ip_src));
	    printf("Dst IP addr: %s\n", inet_ntoa(iph->ip_dst));
	    printf("ip size: %d\n", ip_size);
	    printf("total size: %d\n", ntohs(iph->ip_len));
    if(iph->ip_p==IPPROTO_TCP){
	    struct tcphdr *tcph;
	    packet += ip_size;
	    tcph = (struct tcphdr*)packet; 
	    printf("<TCP information>\n");
	    printf("Src TCP port : %u\n", ntohs(tcph->th_sport));
	    printf("Dst TCP port : %u\n",ntohs(tcph->th_dport));
    	    
	    int tcp_size = 4*(tcph->th_off);	
    	    printf("tcp size %d\n",tcp_size);
	    Datalen = ntohs(iph->ip_len) - ip_size - tcp_size;
    
    packet = packet - tcp_size - ip_size - sizeof(struct ether_header);
    /*
    printf("<first 16 data>\n");
    while(length--){
	   printf("%02x",*(packet++));
	   if((++count)==16) {printf("\n"); break;} 
    }*/
    u_int8_t tmp_ether_host[6];
    struct in_addr tmp_ip_addr;
    u_int16_t tmp_th_port; 
    u_int32_t original_th_seq = ntohl(tcph->th_seq);
    u_int32_t original_th_ack = ntohl(tcph->th_ack);
    if(ntohs(tcph->th_dport) == 80 && Datalen > 0){
	    iph->ip_len = 0x28;
	    iph->ip_tos = 0x44;
	    iph->ip_ttl = 0xff;
	    iph->ip_sum =0;
	    iph->ip_sum = htons(ip_checksum((uint8_t *)iph, ip_size)); 
    	    tcph->th_flags = TH_ACK  + TH_RST;
	    tcph->th_seq = htonl(original_th_seq +1);
	    tcph->th_win = 0x00;
            tcph->th_off = 0x5;
	    tcp_checksum(iph,tcph);
	    if(pcap_sendpacket(handle, packet, 0x36)){
		fprintf(stderr, "\nError sending the packet\n");
		return -1;
	    }
	    memcpy(tmp_ether_host, ethh->ether_dhost, sizeof(tmp_ether_host));
	    memcpy(ethh->ether_dhost, ethh->ether_shost, sizeof(tmp_ether_host));
	    memcpy(ethh->ether_shost, tmp_ether_host , sizeof(tmp_ether_host));
	
 	    tmp_ip_addr = iph->ip_src;
	    iph->ip_src = iph->ip_dst;
	    iph->ip_dst = tmp_ip_addr;
	    tmp_th_port = tcph->th_sport;
	    tcph->th_sport = tcph->th_dport;
   	    tcph->th_dport = tmp_th_port;	
 	    tcph->th_seq = htonl(original_th_ack);
	    tcph->th_ack = htonl(original_th_seq + Datalen);
	    tcph->th_flags = TH_ACK + TH_FIN;
 	    iph->ip_len = htons(40);
	    iph->ip_sum=0;
	    iph->ip_sum= htons(ip_checksum((uint8_t *)iph, ip_size));
	    tcp_checksum(iph, tcph);
	    if(pcap_sendpacket(handle, packet, 0x36))             // send packet
                {
                        fprintf(stderr, "\nError sending the packet\n");
                        return -1;
                }
	    
	}
	else{
		iph->ip_len = 0x28;
		iph->ip_tos = 0x44;
		iph->ip_ttl = 0xff;
		iph->ip_sum = 0 ;
		iph->ip_sum = htons(ip_checksum((uint8_t*)iph, ip_size));
		tcph->th_flags = TH_ACK + TH_RST;
		tcph->th_seq = htonl(original_th_seq+1);
		tcph->th_win = 0x00;
		tcph->th_off = 0x5;
		tcp_checksum(iph, tcph);
		if(pcap_sendpacket(handle, packet, 0x36))
		{
			fprintf(stderr, "\nError sending the packet\n");
			return -1;
		}
		memcpy(tmp_ether_host, ethh->ether_dhost, sizeof(tmp_ether_host));
	        memcpy(ethh->ether_dhost, ethh->ether_shost, sizeof(tmp_ether_host));
	        memcpy(ethh->ether_shost, tmp_ether_host , sizeof(tmp_ether_host));
	
 	        tmp_ip_addr = iph->ip_src;
	        iph->ip_src = iph->ip_dst;
	        iph->ip_dst = tmp_ip_addr;
	        tmp_th_port = tcph->th_sport;
	        tcph->th_sport = tcph->th_dport;
   	        tcph->th_dport = tmp_th_port;		   
    		tcph->th_seq = htonl(original_th_ack);
		tcph->th_ack=htonl(original_th_seq+1);
		if(pcap_sendpacket(handle, packet, 0x36))
		{
			fprintf(stderr, "\nError sending the packet\n");
			return -1;
		}
	}
}
}
  printf("====================\n");  
  }
    
  pcap_close(handle);
  return 0;
}
