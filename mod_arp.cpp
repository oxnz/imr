// mod_arp.cpp

#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>

#include "mod_eth.h"
#include "mod_arp.h"

// send_arp_reply(): send 'src_ip' is at 'src_mac' to 'dest_ip'
int send_arp_reply( int bpf,
		    const unsigned char* src_mac,
		    unsigned long src_ip,
		    const unsigned char* dest_mac,
		    unsigned long dest_ip )
{
  if( bpf == -1 )
    {
      fprintf( stderr, "ERROR: Invalid BPF device: %i\n", bpf );
      return( -1 );
    }
  else if( !( src_mac && 
	      src_ip && 
	      dest_mac &&
	      dest_ip ) )
    {
      fprintf( stderr, 
	       "ERROR: Invalid parameters for send_arp_reply!\n" );
      return( -2 );
    }

  // create and send the ARP packet
  
  arp_packet packet;
  memset( &packet, 0, sizeof( packet ) );
  
  packet.hardware_type = htons( 1 ); // ethernet
  packet.proto_type = htons( 0x0800 ); // IP
  packet.hardware_addr_length = 6;
  packet.proto_addr_length = 4;
  packet.opcode = htons( 2 ); // ARP reply
  
  // copy MAC / IP addresses

  memcpy( packet.src_mac, src_mac, sizeof( packet.src_mac ) );
  memcpy( packet.src_ip, &src_ip, sizeof( packet.src_ip ) );
  memcpy( packet.dest_mac, dest_mac, sizeof( packet.dest_mac ) );
  memcpy( packet.dest_ip, &dest_ip, sizeof( packet.dest_ip ) );

  return( send_eth_frame( bpf, 
			  dest_mac,
			  src_mac,
			  htons( 0x0806 ), // ARP packet type
			  reinterpret_cast<unsigned char*>( &packet ),
			  sizeof( arp_packet ) ) );
}
