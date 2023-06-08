```
   ___   ___  ___    _____  _____________________ 
  / _ | / _ \/ _ \  / __/ |/ /  _/ __/ __/ __/ _ \
 / __ |/ , _/ ___/ _\ \/    // // _// _// _// , _/
/_/ |_/_/|_/_/    /___/_/|_/___/_/ /_/ /___/_/|_|  

```

### ARP Spoof Detector v0.1 [linux] (beta)

This tool will sniff for ARP packets in the interface and can possibly detect if there is an ongoing ARP spoofing attack. 

```
Available arguments: 
----------------------------------------------------------
-h or --help:			Print this help text.
-l or --lookup:			Print the available interfaces.
-i or --interface:		Provide the interface to sniff on.
-v or --version:		Print the version information.
----------------------------------------------------------

Usage: ./arpsniffer -i <interface> [You can look for the available interfaces using -l/--lookup]
```

### How to compile?

1. You should have `libpcap` installed on your linux system. If you don't have, you can do it with the following command

```
$ sudo apt-get install libpcap-dev
```

2. You can compile with the following command

```
$ gcc arp_sniffer.c -o arpsniffer -lpcap
```
