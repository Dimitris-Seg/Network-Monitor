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
 *@file sniffer.h
 *
 * Computer Science Department, University Of Crete
 */

#ifndef CAPTURE_H
#define CAPTURE_H

#include "../utils/general_types.h"
#include "../storage/host_hashtable.h"
//
#include <pcap/pcap.h>
//

extern char errbuf[PCAP_ERRBUF_SIZE];

host_hashtable_t parse_network_traffic(string filename);

#endif