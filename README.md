This program based on linux netfilter is designed to accomplish arp flood limit.

It has two main parts:

1) netfilter kernel module

   Compiling the kernel module(arp_defense.ko) and installing it, this kernel module is responsible for receiving commonds from application program(arp_defense_client), then parses arguments and will be achieve limiting and filtering arp flood packets by TBF algorithm.
   
2) userspace application

   This client program sends filter rules by linux netlink communicating with kernel module(arp_defense.ko).
   
   Example:
   
   arp_defense_client add eth0 50 50
   
   It means that kernel module(arp_defense.ko) will add a filter rule, if arp packets(IP+MAC) on eth0 interface extends 50 per second, device kernel module will drop thess arp packets maked flood attack.  

You should read module makefile carefully and choose the changes that best suit you.
