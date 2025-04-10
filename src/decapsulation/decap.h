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
 *@file decap.h
 *
 * Computer Science Department, University Of Crete
 */

#ifndef DECAP_H
#define DECAP_H

#include "../utils/general_types.h"
//
#include <pcap/pcap.h>
//

typedef struct ether_data {
    u_char* data_start;
    uint16_t protocol;
} ether_data_t;

typedef struct il_data { // Internet layer data
    u_char* data_start;
    char* source_ip;
    char* dest_ip;
    uint8_t protocol;
} il_data_t;

typedef struct tl_data { // Transport layer data
    u_int16_t source_port;
    u_int16_t dest_port;
} tl_data_t;

// bytes refers to the start of the ethernet header
ether_data_t decapsulate_ether(const u_char* bytes);

// bytes refers to the start of the ip header
il_data_t decapsulate_ipv4(const u_char* bytes);

// bytes refers to the start of the tcp header
tl_data_t decapsulate_tcp(const u_char* bytes);

// bytes refers to the start of the udp header
tl_data_t decapsulate_udp(const u_char* bytes);

#endif