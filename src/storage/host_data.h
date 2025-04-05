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
 *@file host_data.h
 *
 * Computer Science Department, University Of Crete
 */

#ifndef HOST_DATA_H
#define HOST_DATA_H

#include "../utils/general_types.h"
#include "linked_list.h"
//

typedef struct host_data host_data_t;

#define EMPTY_HOST_DATA (host_data_t){.host_ip=NULL, .n_outgoing=0, .total_bytes=0, .source_ports=NULL, .dest_ports=NULL, .protocols={FALSE, FALSE}}

struct host_data {
    string host_ip;
    unsigned int n_outgoing;
    unsigned int total_bytes;
    Linked_list_t source_ports;
    Linked_list_t dest_ports;
    bool protocols[2]; // 0: tcp, 1: udp
};

#endif