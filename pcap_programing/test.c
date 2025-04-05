#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ether.h>
#include"header.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);

    printf("---------------------\n");
    // Ethernet address
    printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
    printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));
    
    //IP address
    printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));
   
    //TCP port
    printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
    printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));

    //Message
    printf("Message: ");
    char *msg = (char *)(tcp + sizeof(struct tcpheader));
    
    for(int i=0;i<16;i++){
            printf("%02x ", msg[i]);
        }
    printf("\n");
    printf("---------------------\n");
}

int main(){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
          char filter_exp[] = "tcp";
          bpf_u_int32 net;
    
    //1st: Open live pcap session on NIC with name eth0

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    // if we can't capture the network, stop the capture
    if (handle == NULL) {
        fprintf(stderr, "fail: %s\n", errbuf);
        return 1;
    }
    
    pcap_compile(handle, &fp, filter_exp, 0, net);
          if (pcap_setfilter(handle, &fp) !=0) {
                          pcap_perror(handle, "Error:");
              exit(EXIT_FAILURE);
  }
                // 2nd: capture the packets
    pcap_loop(handle, 0, got_packet, NULL);
    
                // 3rd: finish the capture
    pcap_close(handle);

    return 0;
}

