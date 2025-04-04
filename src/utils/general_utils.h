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
 *@file general_utils.h
 *
 * Computer Science Department, University Of Crete
 */

 #ifndef GENERAL_UTILS_H
 #define GENERAL_UTILS_H
 
 #include "general_types.h"
 //
 #include <stdlib.h>
 //
 
 void* safe_malloc(size_t size);
 void* deepCopy(const void* src, size_t size);
 void safe_free(void* mem);
 size_t hash_int(int value, size_t length);
 size_t hash_string(string value, size_t length);
 int min(int a, int b);
 int max(int a, int b);
 int myfloor(float val); // Only works with positive numbers for performace
 int myceil(float val);  // Only works with positive numbers for performace
 
 #endif