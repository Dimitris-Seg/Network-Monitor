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
 *@file constants.h
 *
 * Computer Science Department, University Of Crete
 */

// File reading
#define INPUT_BUFFER_SIZE 4112

// Resizable string 
#define RS_STRING_DEFAULT_SIZE 64
#define RS_STRING_GROWTH_RATE 64

// Host hashtable
#define DEFAULT_HOST_HASHTABLE_LEN 64
 