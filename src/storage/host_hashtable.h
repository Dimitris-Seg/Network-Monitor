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
 *@file host_hashtable.h
 *
 * Computer Science Department, University Of Crete
 */

#ifndef HOST_HASHTABLE_H
#define HOST_HASHTABLE_H

#include "../utils/general_types.h"
#include "host_data.h"
//
#include "linked_list.h"
//

typedef struct host_hashtable_entry *host_hashtable_entry_t;
typedef struct host_hashtable *host_hashtable_t;
struct host_hashtable_entry* new_host_hashtable_entry(string _key, host_data_t _value);
void delete_host_hashtable_entry(struct host_hashtable_entry* obj);
struct host_hashtable* new_host_hashtable();
void delete_host_hashtable(struct host_hashtable* obj);
host_data_t* host_hashtable_put(host_hashtable_t hashtable, string key, host_data_t value);
host_data_t* host_hashtable_find(host_hashtable_t hashtable, string key);
void host_hashtable_map(host_hashtable_t hashtable, void (*mapping)(host_hashtable_entry_t, void*), void* args);

struct host_hashtable_entry {
    string key;
    host_data_t value;
    host_hashtable_entry_t next;
};

struct host_hashtable {
    host_hashtable_entry_t* table;
};

#endif