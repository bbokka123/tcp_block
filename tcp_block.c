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
  
  int data_size;


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
    //header packet값을 통해 패킷 정보를 얻어온다.
    if(res==0) continue;
    if(res == -1 || res == -2) break;
    printf("%u bytes captured\n",header->caplen);

    int count =1 ;
    int length= header ->len;
    
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
	    //만약 packet 이 http라면
	    if(ntohs(tcph->th_dport) == 80){
		
		printf("its http!\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
	    	
		tcph->th_flags = TH_RST+TH_ACK;	
	        data_size = ntohs(iph->ip_len) - ip_size - tcp_size;
		if(data_size ==0){ 	
		tcph->th_seq += 1;
		tcph->th_ack += 1; 
		tcph->th_win = 0;
	        }
		else{
		tcph->th_seq += data_size;
		tcph->th_win=0;
		}
		//forward
		packet = packet - ip_size - sizeof(struct ether_header);
		if(pcap_sendpacket(handle, (unsigned char *)packet, length)){       
	                fprintf(stderr, "\nError sending the packet\n");
	                exit(0);
	        }
	        //backward
		tcph->th_flags = TH_FIN;
	 	for(int i=0; i<6; i++){
			tmp[i] = ethh->ether_dhost[i];
			ethh->ether_dhost[i] = ethh->ether_shost[i];
			ethh->ether_shost[i] = tmp[i];
		}
		//ip 주소 변경
		tmp_ip  = iph->ip_src;
		iph->ip_src = iph->ip_dst;
	        iph->ip_dst = tmp_ip;
		//tcp port 변경	
	    	tmp_port = tcph-> th_sport;
		tcph->th_sport = tcph->th_dport;
		tcph->th_dport = tmp_port;
 	        
		tmp_syn = tcph -> th_seq;
		tcph->th_ack = tcph->th_seq;
		tcph->th_seq = tmp_syn;
		

		if(pcap_sendpacket(handle, (unsigned char *)packet, length)){       
	                fprintf(stderr, "\nError sending the packet\n");
	                exit(0);
	        }
	
		}
	    
	    //packet이 http가 아니라면
	    else{
		tcph->th_flags = TH_RST+TH_ACK;
		//forward
		packet = packet - ip_size - sizeof(struct ether_header);
	        data_size = ntohs(iph->ip_len) - ip_size - tcp_size;
		
		if(data_size ==0){ 	
		tcph->th_seq += 1;
		tcph->th_ack += 1; 
		tcph->th_win = 0;
		}
		else{
		tcph->th_seq += data_size;
		tcph->th_win=0;
		}
		if(pcap_sendpacket(handle, (unsigned char *)packet, length)){       
	                fprintf(stderr, "\nError sending the packet\n");
	                exit(0);
	        }
		
		//backward
		for(int i=0; i<6; i++){
			tmp[i] = ethh->ether_dhost[i];
			ethh->ether_dhost[i] = ethh->ether_shost[i];
			ethh->ether_shost[i] = tmp[i];
		}
		//ip 주소 변경
		tmp_ip  = iph->ip_src;
		iph->ip_src = iph->ip_dst;
	        iph->ip_dst = tmp_ip;
		//tcp port 변경	
	    	tmp_port = tcph-> th_sport;
		tcph->th_sport = tcph->th_dport;
		tcph->th_dport = tmp_port;
 	        
		tmp_syn = tcph -> th_seq;
		tcph->th_ack = tcph->th_seq;
		tcph->th_seq = tmp_syn;
		
		
		if(pcap_sendpacket(handle, (unsigned char *)packet, length)){       
	                fprintf(stderr, "\nError sending the packet\n");
	                exit(0);
	        }

	    }
    }
    }
    printf("<first 16 data>\n");
    while(length--){
	   printf("%02x",*(packet++));
	   if((++count)==16) {printf("\n"); break;} 
    }
     	    
    
    	
  printf("====================\n");  
  }
    
  pcap_close(handle);
  return 0;
}
