//  mod_eth.h -- Ethernet frame stuff

#ifndef IMR_MOD_ETH_H
#define IMR_MOD_ETH_H

// single ethernet_frame
struct ethernet_frame
{
  unsigned char dest_addr[ 6 ];
  unsigned char src_addr[ 6 ];
  unsigned short int type;
};

int send_eth_frame( int bpf, 
		    const unsigned char* dest_addr, 
		    const unsigned char* src_addr,
		    unsigned short int type,
		    const unsigned char*  payload,
		    unsigned int payload_size );

#endif
