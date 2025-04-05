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
 *@file general_utils.c
 *
 * Computer Science Department, University Of Crete
 */

 #include "general_utils.h"
 #include "logging.h"
 //
 #include <stdio.h>
 #include <string.h>
 #include <assert.h>
 //
 
void* safe_malloc(size_t size)
{
    void* allocated = malloc(size);
    if (allocated == NULL)
    {
        ERROR("Malloc: Unable to allocate memory.");
        exit(EXIT_FAILURE);
    }
    return allocated;
}

void* deepCopy(const void* src, size_t size) {
    // Allocate memory for the new object
    void* copy = safe_malloc(size);

    // Copy the contents of the original object
    memcpy(copy, src, size);

    return copy;
}

void safe_free(void* mem)
{
    if(!mem){
        ERROR("Free: Invalid memory pointer 'NULL'");
        exit(EXIT_FAILURE);
    }

    free(mem);
}

size_t hash_string(string value, size_t length){
    assert(value);

    size_t hash = 0;
    while(*value){
        hash+=*value;
        ++value;
    }
    return hash%length;
}