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
 *@file decap.c
 *
 * Computer Science Department, University Of Crete
 */

#include "decap.h"
#include "../utils/logging.h"
//
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <assert.h>
//

// Decapsulate ethernet header
ether_data_t decapsulate_ether(const u_char* bytes){
    assert(bytes);

    ether_data_t eth_data;

    struct ethhdr* eth_header = (struct ethhdr*)bytes;
    eth_data.protocol = ntohs(eth_header->h_proto);
    eth_data.data_start = (u_char*)(bytes+sizeof(struct ethhdr));
    return eth_data;
}

il_data_t decapsulate_ipv4(const u_char* bytes){
    il_data_t ip_data;

    // The decapsulated contents (ip-layer encapsulation) is after the ethernet header
    struct iphdr* ip_header = (struct iphdr*)bytes;

    // Retrieve the source and destination ip addresses
    struct in_addr src_ip;
    src_ip.s_addr = ip_header->saddr;
    ip_data.source_ip = strdup(inet_ntoa(src_ip));
    //
    struct in_addr dest_ip;
    dest_ip.s_addr = ip_header->daddr;
    ip_data.dest_ip = strdup(inet_ntoa(dest_ip));

    ip_data.protocol = ip_header->protocol;
    ip_data.data_start = (u_char*)(bytes+ ip_header->ihl * 4);

    return ip_data;
}

tl_data_t decapsulate_tcp(const u_char* bytes){
    tl_data_t tl_data;

    struct tcphdr* tcp_header = (struct tcphdr*)bytes;
    tl_data.source_port = ntohs(tcp_header->source);
    tl_data.dest_port = ntohs(tcp_header->dest);

    return tl_data;
}

tl_data_t decapsulate_udp(const u_char* bytes){
    tl_data_t tl_data;

    struct udphdr* udp_header = (struct udphdr*)bytes;
    tl_data.source_port = udp_header->source;
    tl_data.dest_port = udp_header->dest;

    return tl_data;
}

// void decapsulate_packet(const u_char* bytes){
//     // First, ethernet header comes off
//     struct ethhdr* eth_header = (struct ethhdr*)bytes;

//     // Check internet layer protocol, we only care about IPv4 here
//     if(ntohs(eth_header->h_proto) == ETH_P_IP) {
//         // The decapsulated contents (ip-layer encapsulation) is after the ethernet header
//         struct iphdr* ip_header = (struct iphdr*)(bytes+sizeof(struct ethhdr));

//         // Retrieve the source and destination ip addresses
//         struct in_addr src_ip;
//         src_ip.s_addr = ip_header->saddr;
//         INFO("Sender: %s", inet_ntoa(src_ip));
//         //
//         struct in_addr dest_ip;
//         src_ip.s_addr = ip_header->daddr;
//         INFO("Destination: %s", inet_ntoa(dest_ip));

//         switch(ip_header->protocol){
//         case IPPROTO_TCP: {// TCP transport-layer protocol
//                 struct tcphdr* tcp_header = (struct tcphdr*)(ip_header + ip_header->ihl * 4);
//                 INFO("TCP Source port: %u", tcp_header->source);
//                 INFO("TCP Dest port: %u", tcp_header->dest);
//             }
//             break;
//         case IPPROTO_UDP: {// UDP transport-layer protocol
//                 struct udphdr* udp_header = (struct udphdr*)(ip_header + ip_header->ihl * 4);
//                 INFO("UDP Source port: %u", udp_header->source);
//                 INFO("UDP Dest port: %u", udp_header->dest);
//             }
//             break;
//         }
//     }
// }

