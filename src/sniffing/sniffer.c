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
 *@file sniffer.c
 *
 * Computer Science Department, University Of Crete
 */

#include "sniffer.h"
#include "../utils/logging.h"
//
#include <assert.h>
//

//
char errbuf[PCAP_ERRBUF_SIZE];
//

void sniffer_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* bytes){
    // Analyze and decapsulate...
}

void parse_network_traffic(string filename){
    assert(filename);

    pcap_t* handle = pcap_open_offline(filename, errbuf);

    if(handle){
        pcap_loop(handle, -1, sniffer_callback, NULL);
        pcap_close(handle);
    }else{
        ERROR("Failed to open file %s for reading: %s", filename, errbuf);
    }
}

