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
    // printf("ARP Spoof Detector v0.1\n");
    exit(1);
}


void print_help(char *bin){
    printf("ARP Spoof Detector v0.1\n\n");
    printf("Available arguments : \n");
    printf("------------------------------------------------------\n");
    printf("--help or -h:\t\tPrint this help text.\n");
    printf("--lookup or -l\t\tPrint the available interfaces.\n");
    printf("--interface or -i\tProvide the interface to sniff on.\n");
    printf("------------------------------------------------------\n");
    printf("Usage: %s -i <interface> [You can look for the available interface using -l/ --lookup]\n", bin);
    exit(1);
}

int main(int argc, char *argv[]){

    if(argc < 2 || strcmp("-h", argv[1]) == 0 || strcmp("--help", argv[1]) == 0 ){
        print_help(argv[0]);
    }else if(strcmp("-v", argv[1]) == 0 || strcmp("--version", argv[1]) == 0 ){
        print_version();
    }else if(strcmp("-i", argv[1]) == 0 || strcmp("--interface", argv[1]) == 0 ){
        print_available_interface();
    }
}

