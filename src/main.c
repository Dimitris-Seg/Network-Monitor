/**
 * Implementation of an offline network traffic analyzer
 *
 *@author Dimitris Segkesser, A.M.: 5006
 *@date 04/04/2025
 *
 *@brief This is an implementation of an offline network traffic analyzer, 
 * observing pre-captured network traffic from a .pcap file and gathering
 * useful information about the interactions of a specific host with 
 * other hosts.
 *
 *@file main.c
 *
 * Computer Science Department, University Of Crete
 */

#include "./utils/general_types.h"
#include "./utils/logging.h"
#include "./cryptohash/cryptohash.h"
#include "./sniffing/sniffer.h"
//

void print_help(string name){
    PRINTLN("Usage: %s <source pcap file> <filter ip address>", name);
}

int main(int argc, string* argv){
    if(argc<3){
        ERROR("Missing command-line arguments for .pcap filename and/or filtered ip address");
        print_help(argv[0]);
        exit(EXIT_FAILURE);
    }

    // Input args should be available here

    PRINT_WATERMARK();

    string pcap_filename = argv[1];
    string filter_ip_addr = argv[2];

    INFO("Application started with argument '%s'", pcap_filename);
    INFO("MD5 hash:    %s", md5_hash_file(pcap_filename));
    INFO("SHA256 hash: %s", sha256_hash_file(pcap_filename));
    parse_network_traffic(pcap_filename);
}