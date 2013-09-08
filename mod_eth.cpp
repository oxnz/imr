// mod_eth.cpp

#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "mod_eth.h"

// send_eth_frame(): Creates a new frame based on the given parameters
// to send 'payload' via 'bpf'
int send_eth_frame( int bpf, 
		    const unsigned char* dest_addr, 
		    const unsigned char* src_addr,
		    unsigned short int type,
		    const unsigned char*  payload,
		    unsigned int payload_size )
{
  // check for common errors
  
  if( bpf == -1 )
    {
      fprintf( stderr, "ERROR: Invalid BPF device: %i\n", bpf );
      return( -1 );
    }
  else if( payload == NULL || payload_size == 0 )
    {
      fprintf( stderr, "ERROR: Thou shalt not send a 'NULL' payload!\n" );
      return( -2 );
    }

  // prepare a buffer that holds the Ethernet frame and the payload

  ethernet_frame frame;
  
  memcpy( frame.dest_addr, dest_addr, sizeof( frame.dest_addr ) );
  memcpy( frame.src_addr, src_addr, sizeof( frame.src_addr ) );
  frame.type = type;

  // TODO:
  // it could be a good idea to check whether the payload is too
  // big...

  unsigned char* buf = new unsigned char[ sizeof( frame ) + payload_size ];
  memcpy( buf, &frame, sizeof( frame ) );
  memcpy( buf + sizeof( frame ), payload, payload_size );

  // send the frame
  
  int sent_bytes = write( bpf, buf, sizeof( frame) + payload_size );
  
  delete[] buf;
  return( sent_bytes );
}
