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
 *@file linked_list.c
 *
 * Computer Science Department, University Of Crete
 */

#include "linked_list.h"
#include "../utils/general_utils.h"
//
#include <stdlib.h>
#include <assert.h>
//

Linked_list_node_t new_Linked_list_node(unsigned int _value){
    Linked_list_node_t new_obj = (Linked_list_node_t)safe_malloc(sizeof(struct Linked_list_node));
    new_obj->value = _value;
    new_obj->next = NULL;
    return new_obj;
}

void delete_Linked_list_node(Linked_list_node_t obj){
    safe_free(obj);
}

Linked_list_t new_Linked_list(){
    Linked_list_t new_obj = (Linked_list_t)safe_malloc(sizeof(struct Linked_list));
    new_obj->head = NULL;
    return new_obj;
}

void delete_Linked_list(Linked_list_t obj){
    assert(obj);

    Linked_list_node_t p = obj->head;
    while(p){
        
        Linked_list_node_t prev = p;
        p = p->next;
        delete_Linked_list_node(prev);
    }
    safe_free(obj);
}

void Linked_list_insert(Linked_list_t list, unsigned int value){
    assert(list);

    Linked_list_node_t new_node = new_Linked_list_node(value);
    new_node->next = list->head;
    list->head = new_node;
}

bool Linked_list_contains(Linked_list_t list, unsigned int value){
    assert(list);

    Linked_list_node_t it = list->head;
    while(it && it->value!=value)
        it=it->next;

    return (it!=NULL);
}