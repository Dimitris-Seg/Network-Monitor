# Assignment 1 – Part 2: Network Traffic Analyzer

- Course: HY-457
- Computer Science Department, University Of Crete
- Author: Dimitris Segkesser, A.M.: 5006

# Brief

This is an implementation of a simple offline Network Traffic Analyzer, 
using the pcap library. The program is able to 'sniff out' packets
sourcing from a specified host (based on the host's IP) and display
general statistics like the number of packets sent to each host,
the total bytes communicated, the source/dest ports and the protocols used
to facilitate the connections.

# Options

The program expects 2 commandline arguments, the first one specifies the input
.pcap file which will be the source of the analyzed data, and the second argument
specifies the filtered IP address, meaning the sole source address around which 
the analysis is going to focus.

# Execution and testing

The provided Makefile can be used to build the executable, and run it with a specified input file & filter IP address.
The following targets are supported:
 1) all
 2) clean
 3) test

Supported Makefile targets:

1. `all` – Builds the application  
2. `clean` – Removes the build directory  
3. `test` – Runs the executable, where the arguments have to be specified as:
    `make test <path-to-input-pcap-file> <filter-ip-address>`, e.g.: `make test ./inputs/traffic.pcap 192.168.153.1` 
