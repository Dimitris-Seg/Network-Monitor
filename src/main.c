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
#include "./storage/host_hashtable.h"
//

void print_host_entry(host_hashtable_entry_t e, void* extras){
    PRINTLN();
    PRINTLN("IP: %s", e->value.host_ip);
    PRINTLN("%u outgoing packets [%u Bytes]", e->value.n_outgoing, e->value.total_bytes);

    // Iterate over all source ports
    PRINT("Source ports: ");
    Linked_list_node_t source_port_p = e->value.source_ports->head;
    while(source_port_p){
        PRINT("%u%s", source_port_p->value, source_port_p->next?", ":"");
        source_port_p = source_port_p->next;
    }
    PRINTLN();
    //

    // Iterate over all destination ports
    PRINT("Destination ports: ");
    Linked_list_node_t dest_port_p = e->value.dest_ports->head;
    while(dest_port_p){
        PRINT("%u%s", dest_port_p->value, dest_port_p->next?", ":"");
        dest_port_p = dest_port_p->next;
    }
    PRINTLN();
    //

    bool tcp_used = e->value.protocols[0];
    bool udp_used = e->value.protocols[1];

    PRINTLN("Protocol%s: %s%s%s", (tcp_used&&udp_used)?"s":"", tcp_used?"TCP":"", (tcp_used&&udp_used)?", ":"", udp_used?"UDP":"");
}

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
    string filter_ip_addr =argv[2];

    INFO("Application started with argument '%s'", pcap_filename);
    INFO("MD5 hash:    %s", md5_hash_file(pcap_filename));
    INFO("SHA256 hash: %s", sha256_hash_file(pcap_filename));
    host_hashtable_t hosts = parse_network_traffic(pcap_filename, filter_ip_addr);
    host_hashtable_map(hosts, print_host_entry, NULL);
    delete_host_hashtable(hosts);
}