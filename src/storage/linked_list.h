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
 *@file linked_list.h
 *
 * Computer Science Department, University Of Crete
 */

#ifndef LINKED_LIST_H
#define LINKED_LIST_H

#include "../utils/general_types.h"
//
#include <stdlib.h>
//

typedef struct Linked_list_node *Linked_list_node_t;
typedef struct Linked_list *Linked_list_t;
struct Linked_list_node* new_Linked_list_node(unsigned int _value);
void delete_Linked_list_node(struct Linked_list_node* obj);
struct Linked_list* new_Linked_list();
void delete_Linked_list(struct Linked_list* obj);
void Linked_list_insert(Linked_list_t list, unsigned int value);
bool Linked_list_contains(Linked_list_t list, unsigned int value);

struct Linked_list_node {
    unsigned int value;
    Linked_list_node_t next;
};

struct Linked_list {
    Linked_list_node_t head;
};

#endif