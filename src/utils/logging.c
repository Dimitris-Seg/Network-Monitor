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
 *@file logging.c
 *
 * Computer Science Department, University Of Crete
 */

 #include "./logging.h"
 //
 #include<time.h>
 //
 
 string get_current_date() {
     static char buffer[11]; // YYYY-MM-DD + \0
 
     time_t rawtime;
     struct tm * timeinfo;
 
     time(&rawtime);
     timeinfo = localtime(&rawtime);
 
     strftime(buffer, sizeof(buffer), "%Y-%m-%d", timeinfo);
 
     return buffer;
 }
 
 string get_current_time() {
     static char buffer[9]; // hh:mm:ss + \0
 
     time_t rawtime;
     struct tm * timeinfo;
 
     time(&rawtime);
     timeinfo = localtime(&rawtime);
 
     int hours = timeinfo->tm_hour;
     int minutes = timeinfo->tm_min;
     int seconds = timeinfo->tm_sec;
 
     // Print the time in HH:MM:SS format
     snprintf(buffer, sizeof(buffer), "%02d:%02d:%02d", hours, minutes, seconds);
 
     return buffer;
 }