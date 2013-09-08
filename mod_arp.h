// mod_arp.h -- ARP packet data types / functions

#ifndef IMR_MOD_ARP_H
#define IMR_MOD_ARP_H

// ARP packet structure
struct arp_packet
{
  unsigned short int hardware_type;
  unsigned short int proto_type;
  unsigned char hardware_addr_length;
  unsigned char proto_addr_length;
  unsigned short int opcode;
  unsigned char src_mac[ 6 ];
  unsigned char src_ip[ 4 ];
  unsigned char dest_mac[ 6 ];
  unsigned char dest_ip[ 4 ];

  // TODO:
  // you could add padding here if you want to
};

int send_arp_reply( int bpf,
		    const unsigned char* src_mac,
		    unsigned long src_ip,
		    const unsigned char* dest_mac,
		    unsigned long dest_ip );
#endif
