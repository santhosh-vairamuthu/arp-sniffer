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
    printf("------------------------------------------------------\n");
    printf("--help or -h:\t\tPrint this help text.\n");
    printf("--lookup or -l\t\tPrint the available interfaces.\n");
    printf("--interface or -i\tProvide the interface to sniff on.\n");
    printf("------------------------------------------------------\n");
    printf("Usage: %s -i <interface> [You can look for the available interface using -l/ --lookup]\n", bin);
    exit(1);
}

int sniff_packet(char *user_dev_name){
    char *device_name, *net_addr, *net_mask;
    int return_code,i;
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *packet_descriptor;
    pcap_if_t *interface;
    const u_char *packet;
    struct pcap_pkthdr header;
    struct ether_header *ether_ptr;
    u_char *hard_ptr;

    // pcap_findalldevs(&interface, error);
    // while(strcmp(user_dev_name, interface->name) != 0 ){
    //     interface = interface->next;
    // }

	// if(strcmp(user_dev_name,interface->name) == 0){
	// 	device_name  = interface->name;
	// }else{
	// 	printf("Invalid Device name\n");
	// 	printf("Quitting........\n");
	// 	return 0;
	// }
	device_name  = user_dev_name;

	packet_descriptor = pcap_open_live(device_name, BUFSIZ, 0,1, error);
    if(packet_descriptor == NULL){
        printf("%s\n",error);
        return -1;
    }

    packet = pcap_next(packet_descriptor, &header);
    if(packet == NULL){
        printf("ERROR IN PACKET CAPTURING\n");
        return -1;
    }else{
        printf("Received a packet with length  %d\n", header.len);
        printf("Received at %s\n", ctime((const time_t*) &header.ts.tv_sec));
        printf("Ethernet address constant length is %d\n", ETHER_HDR_LEN);

        ether_ptr = (struct ether_header *)packet;

        if(ntohs(ether_ptr->ether_type) == ETHERTYPE_IP){
            printf("Ethernet type hex: 0x%x; dec: %d is an IP PACKET\n", ETHERTYPE_IP, ETHERTYPE_IP);
        }else if(ntohs(ether_ptr->ether_type) == ETHERTYPE_ARP){
            printf("Ethernet type hex: 0x%x; dec: %d is an ARP PACKET\n", ETHERTYPE_ARP,ETHERTYPE_ARP);
        }else{
            printf("Ethernet type hex: 0x%x; dec: %d is NOT an IP OR ARP PACKET\n", ntohs(ether_ptr->ether_type),ntohs(ether_ptr->ether_type));
            return -1;
        }

        i = ETHER_ADDR_LEN; 
        hard_ptr = ether_ptr->ether_dhost;
        printf("DESTINATION ADDRESS: ");
        do{
            printf("%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *hard_ptr++);
        }while(--i>0);
        printf("\n");

        i = ETHER_ADDR_LEN;
        hard_ptr = ether_ptr->ether_shost;
        printf("SOURCE ADDRESS: ");
        do{
            printf("%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *hard_ptr++);
        }while(--i>0);
        printf("\n");
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
