#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include<pcap.h>   //libcap library
#include<errno.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>
#include<net/ethernet.h>


#define ARP_REQUEST 1
#define ARP_RESPONSE 2

typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
    uint16_t htype;                 // Hardware Type
    uint16_t ptype;                 // Protocol Type
    uint8_t hlen;                   // Hardware Address (MAC Address) Length
    uint8_t plen;                   // Protocol Address Length
    uint16_t opcode;                // Operational Code [Request/Response]
    uint8_t sender_mac[6];          // Sender MAC Address
    uint8_t sender_ip[4];           // Sender IP Address
    uint8_t target_mac[6];          // Target MAC Address
    uint8_t target_ip[4];           // Target IP Address
};

int print_available_interface(){
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interface, *temp;
    int i=0;
    if(pcap_findalldevs(&interface, error) == -1){
        printf("Cannot acquire devices\n");
        return -1;
    }
    printf("The available interfaces are : \n");
    for(temp = interface; temp; temp = temp->next){
        printf("~ %d %s\n",++i,temp->name);
    }
    return 0;
}


void print_version(){
    printf("    ___    ____  ____     _____ _   ____________________________     _    ______   ___\n");
    printf("   /   |  / __ \\/ __ \\   / ___// | / /  _/ ____/ ____/ ____/ __ \\   | |  / / __ \\ <  /\n");
    printf("  / /| | / /_/ / /_/ /   \\__ \\/  |/ // // /_  / /_  / __/ / /_/ /   | | / / / / / / / \n");
    printf(" / ___ |/ _, _/ ____/   ___/ / /|  // // __/ / __/ / /___/ _, _/    | |/ / /_/ / / /  \n");
    printf("/_/  |_/_/ |_/_/       /____/_/ |_/___/_/   /_/   /_____/_/ |_|     |___/\\____(_)_/   \n");
    printf("\nARP Spoof Detector v0.1\n\n");
}


void print_help(char *bin){
    printf("Available arguments : \n");
    printf("-----------------------------------------------------------\n");
    printf("--help or -h:\t\tPrint this help text.\n");
    printf("--lookup or -l\t\tPrint the available interfaces.\n");
    printf("--interface or -i\tProvide the interface to sniff on.\n");
    printf("------------------------------------------------------------\n");
    printf("Usage: %s -i <interface> [You can look for the available\n interface using -l/ --lookup]\n", bin);
    printf("------------------------------------------------------------\n");
    exit(1);
}

void print_mac_address(uint8_t mac[6]){
    for(int i=0;i<6;i++){
        printf("%02x", mac[i]);
        if(i!=5){
            printf(":");
        }
    }
    printf("\n");

}

void print_ip_address(uint8_t ip[4]){
    for(int i=0;i<4 ;i++){
        printf("%d", ip[i]);
        if(i!=3){
            printf(".");
        }
    }
    printf("\n");

}

int sniff_packet(char *user_dev_name){
    char *device_name, *net_addr, *net_mask;
    int return_code,i;
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *packet_descriptor;
    pcap_if_t *interface;
    const __u_char *packet;
    struct pcap_pkthdr header;
    struct ether_header *ether_ptr;
    arp_hdr *arp_header = NULL;
    __u_char *hard_ptr;
	device_name  = user_dev_name;

	packet_descriptor = pcap_open_live(device_name, BUFSIZ, 0,1, error);
    if(packet_descriptor == NULL){
        printf("%s\n",error);
        return -1;
    }else{
        printf("Listening on %s...\n", device_name);
    }
    while(1){
        packet = pcap_next(packet_descriptor, &header);
        if(packet == NULL){
            printf("ERROR IN PACKET CAPTURING\n");
            return -1;
        }else{
            ether_ptr = (struct ether_header *)packet;
            if(ntohs(ether_ptr->ether_type) == ETHERTYPE_ARP){
                arp_header = (struct _arp_hdr *)(packet+14); 
                printf("\n------------------------------------------------------------\n");
                printf("Received an ARP packet with length  %d\n", header.len);
                printf("Received at %s\n", ctime((const time_t*) &header.ts.tv_sec));
                printf("Ethernet address constant length is %d\n", ETHER_HDR_LEN);
                printf("Operation Type: %s\n", (ntohs(arp_header->opcode) == ARP_REQUEST ) ? "ARP-REQUEST" : "ARP_RESPONSE" );
                printf("Sender MAC: ");
                print_mac_address(arp_header->sender_mac);
                printf("Sender IP: ");
                print_ip_address(arp_header->sender_ip);
                printf("Target MAC: ");
                print_mac_address(arp_header->target_mac);
                printf("Target IP: ");
                print_ip_address( arp_header->target_ip);
                printf("------------------------------------------------------------\n");


                // i = ETHER_ADDR_LEN; 
                // hard_ptr = ether_ptr->ether_dhost;
                // printf("DESTINATION ADDRESS: ");
                // do{
                //     printf("%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *hard_ptr++);
                // }while(--i>0);
                // printf("\n");

                // i = ETHER_ADDR_LEN;
                // hard_ptr = ether_ptr->ether_shost;
                // printf("SOURCE ADDRESS: ");
                // do{
                //     printf("%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *hard_ptr++);
                // }while(--i>0);
                // printf("\n");
                // printf("------------------------------------------------------------\n");
                
            }
        }
	}
	return 0;
}

int main(int argc, char *argv[]){

    if(argc < 2 || strcmp("-h", argv[1]) == 0 || strcmp("--help", argv[1]) == 0 ){
        print_version();
        print_help(argv[0]);
    }else if(strcmp("-v", argv[1]) == 0 || strcmp("--version", argv[1]) == 0 ){
        print_version();
    }else if(strcmp("-l", argv[1]) == 0 || strcmp("--lookup", argv[1]) == 0 ){
        print_available_interface();
    }else if(strcmp("-i", argv[1]) == 0 || strcmp("--interface", argv[1]) == 0 ){
        if(argc < 3){
			printf("ERROR : Provide an interface to sniff on.\n");
            printf("------------------------------------------------------\n");
			print_available_interface();
			printf("Usage: %s -i <interface> [You can look for the available interface using -l/ --lookup]\n", argv[0]);
		}else{
			return sniff_packet(argv[2]);
		}
    }else{
        printf("Invalid Argument\n");
        print_help(argv[0]);
    }
	return 0;
}
