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
 *@file general_types.h
 *
 * Computer Science Department, University Of Crete
 */


 #ifndef GENERAL_TYPES_H
 #define GENERAL_TYPES_H
 
 #include <stdlib.h>
 
 typedef char* string;
 typedef enum{FALSE, TRUE}bool;
 typedef struct resizable_string resizable_string_t;
 
 void resizable_string_require(resizable_string_t* rs, long remaining);
 void resizable_string_append(resizable_string_t* rs, void* buff, long len);
 string resizable_string_get(resizable_string_t* rs);
 size_t resizable_string_len(resizable_string_t* rs);
 void resizable_string_destroy(resizable_string_t* rs);

 #define INIT_RESIZABLE_STRING \
     (resizable_string_t){.content=NULL, .length=0, .size=0};
 
 struct resizable_string{
     string content;
     long size;
     long length;
 };
 
 #endif