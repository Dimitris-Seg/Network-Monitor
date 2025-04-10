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
#include "../decapsulation/decap.h"
#include "../utils/general_utils.h"
#include "../utils/logging.h"
//
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <assert.h>
//

//
char errbuf[PCAP_ERRBUF_SIZE];
//

struct user_data {
    host_hashtable_t hosts;
    string filter_ip;
};

void sniffer_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* bytes){
    // Analyze and decapsulate...

    struct user_data* data = (struct user_data*)user;
    host_hashtable_t hosts = data->hosts;
    string filter_ip = data->filter_ip;

    ether_data_t ether_data = decapsulate_ether(bytes);
    if(ether_data.protocol==ETH_P_IP){ // We only care about IPv4 packets
        il_data_t il_data = decapsulate_ipv4(ether_data.data_start);
        tl_data_t tl_data;

        if(strcmp(il_data.source_ip, filter_ip)!=0){ // Only keep packets from the filtered ip
            safe_free(il_data.source_ip);
            safe_free(il_data.dest_ip);
            return;
        }

        if(il_data.protocol==IPPROTO_TCP){
            tl_data = decapsulate_tcp(il_data.data_start);
        }else if(il_data.protocol==IPPROTO_UDP){
            tl_data = decapsulate_udp(il_data.data_start);
        }else{
            return; // No further actions for other protocols
        }

        host_data_t* host_data = host_hashtable_find(hosts, il_data.dest_ip);
        if(!host_data){
            host_data_t data = EMPTY_HOST_DATA;
            data.host_ip = il_data.dest_ip;
            host_data = host_hashtable_put(hosts, il_data.dest_ip, data);
        }

        if(!host_data->source_ports){
            host_data->source_ports = new_Linked_list();
        }
        if(!host_data->dest_ports){
            host_data->dest_ports = new_Linked_list();
        }

        if(!Linked_list_contains(host_data->source_ports, tl_data.source_port)){
            Linked_list_insert(host_data->source_ports, tl_data.source_port);
        }

        if(!Linked_list_contains(host_data->dest_ports, tl_data.dest_port)){
            Linked_list_insert(host_data->dest_ports, tl_data.dest_port);
        }
        
        ++host_data->n_outgoing;
        host_data->total_bytes+=header->len;
        host_data->protocols[(il_data.protocol==IPPROTO_UDP)] = TRUE;

        safe_free(il_data.source_ip); // Only source ip is not needed anymore
    }
}

host_hashtable_t parse_network_traffic(string filename, string filter_ip){
    assert(filename);

    pcap_t* handle = pcap_open_offline(filename, errbuf);
    host_hashtable_t hosts = new_host_hashtable();

    if(handle){
        struct user_data data = {.hosts=hosts, .filter_ip=filter_ip};

        INFO("Filtering traffic of %s", filter_ip);

        pcap_loop(handle, -1, sniffer_callback, (u_char*)&data);
        pcap_close(handle);
    }else{
        ERROR("Failed to open file %s for reading: %s", filename, errbuf);
    }

    return hosts;
}

