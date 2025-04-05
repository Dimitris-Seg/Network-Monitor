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

#include "host_hashtable.h"
#include "../utils/constants.h"
#include "../utils/general_utils.h"
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
//

host_hashtable_entry_t new_host_hashtable_entry(string _key, host_data_t _value){
    host_hashtable_entry_t new_obj = (host_hashtable_entry_t)safe_malloc(sizeof(struct host_hashtable_entry));
    new_obj->key = (string)deepCopy(_key, (strlen(_key)+1)*sizeof(char));
    new_obj->value = _value;
    new_obj->next = NULL;
    return new_obj;
}

void delete_host_hashtable_entry(host_hashtable_entry_t obj){
    safe_free(obj->key);
    if(obj->value.source_ports)delete_Linked_list(obj->value.source_ports);
    if(obj->value.dest_ports)delete_Linked_list(obj->value.dest_ports);
    safe_free(obj);
}

host_hashtable_t new_host_hashtable(){
    host_hashtable_t new_obj = (host_hashtable_t)safe_malloc(sizeof(struct host_hashtable));
    new_obj->table = (host_hashtable_entry_t*)calloc(DEFAULT_HOST_HASHTABLE_LEN, sizeof(host_hashtable_entry_t));
    return new_obj;
}

void delete_host_hashtable(host_hashtable_t obj){
    for (size_t i = 0; i < DEFAULT_HOST_HASHTABLE_LEN; i++) {
        host_hashtable_entry_t entry = obj->table[i];
        while (entry) {
            host_hashtable_entry_t temp = entry;
            entry = entry->next;
            delete_host_hashtable_entry(temp);
        }
    }
    safe_free(obj->table);
    safe_free(obj);
}

host_data_t* host_hashtable_put(host_hashtable_t hashtable, string key, host_data_t value){
    assert(hashtable && key);

    size_t hash = hash_string(key, DEFAULT_HOST_HASHTABLE_LEN);
    host_hashtable_entry_t new_entry = new_host_hashtable_entry(key, value);
    new_entry->next = hashtable->table[hash];
    hashtable->table[hash] = new_entry;
    return &(new_entry->value);
}

host_data_t* host_hashtable_find(host_hashtable_t hashtable, string key){
    assert(hashtable);

    size_t hash = hash_string(key, DEFAULT_HOST_HASHTABLE_LEN);
    host_hashtable_entry_t bucket_p = hashtable->table[hash];
    host_hashtable_entry_t prev = NULL;

    while(bucket_p && strcmp(bucket_p->key, key)){
        // if(strlen(bucket_p->key)>1)("KEY: %s\n", bucket_p->key);
        prev = bucket_p;
        bucket_p = bucket_p->next; // Search
    }
    
    return bucket_p?(&bucket_p->value):NULL;
}

void host_hashtable_map(host_hashtable_t hashtable, void (*mapping)(host_hashtable_entry_t, void*), void* args){
    assert(hashtable);

    for(size_t i=0;i<DEFAULT_HOST_HASHTABLE_LEN; ++i){
        host_hashtable_entry_t p = hashtable->table[i];
        while(p){
            mapping(p, args);
            p = p->next;
        }
    }
}
