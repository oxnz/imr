// mod_bpf.cpp

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/bpf.h>
#include <net/if.h>

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>

#include <errno.h>
#include <unistd.h>

#include "mod_bpf.h"


// bpf_open(): Opens the Berkeley Packet Filter device, defines associations
// with 'interface' and returns a file descriptor
int bpf_open( const char* interface )
{
  int bpf = -1;
  char buf[ 11 ] = { 0 };
  
  // TODO:
  // support more than 99 open BPF devices?

  for( int i = 0; i < 99; i++ )
    {
      sprintf( buf, "/dev/bpf%i", i );
      bpf = open( buf, O_RDWR );
      
      if( bpf != -1 )
	break;
    }

  if( bpf == -1 )
    {
      fprintf( stderr, 
	       "ERROR: Could not open BPF device (more than 99? errno = %i)\n", errno );

      return( -1 );
    }

  // associate the BPF device with the requested interface
  
  ifreq bound_if;
  strcpy( bound_if.ifr_name, interface );
  if( ioctl( bpf, BIOCSETIF, &bound_if ) < 0 )
    {
      fprintf( stderr, "ERROR: BIOCSETIF failed with errno = %i\n", errno );
      return( -1 );
    }
  else
    printf( "- BPF: Interface is now set to %s\n", interface );

  return( bpf );
}

// bpf_prepare(): Prepares the BPF device for sending / receiving. Returns
// the BPF's buffer length 
//
// NOTES: timeout is in seconds
int bpf_prepare( int bpf, unsigned int timeout )
{
  int buf_len = 1;

  if( bpf == -1 )
    {
      fprintf( stderr, "ERROR: bpf is -1. What the hell?\n" );
      return( -1 );
    }

  // activate immediate mode
  if( ioctl( bpf, BIOCIMMEDIATE, &buf_len ) == -1 )
    {
      fprintf( stderr, "ERROR: BIOCIMMEDIATE failed with errno = %i\n", errno );
      return( -1 );
    }

  printf( "- BPF: Immediate mode enabled\n" );

  // I'd like to add my own source address
  if( ioctl( bpf, BIOCGHDRCMPLT, &buf_len ) == -1 )
    {
      fprintf( stderr, "ERROR: BIOCGHDRCMPLT failed with errno = %i\n", errno );
      return( -1 );
    }
  
  printf( "- BPF: BIOCGHDRCMPLT is set\n" );
  
  // request buffer length
  if( ioctl( bpf, BIOCGBLEN, &buf_len ) == -1 )
    {
      fprintf( stderr, "ERROR: BIOCGBLEN failed with errno = %i\n", errno );
      return( -1 );
    }
  printf( "- Requested buffer length is %i\n", buf_len );
  
  // set the timeout
  timeval tv_timeout;
  tv_timeout.tv_sec = timeout;
  tv_timeout.tv_usec = 0;
  
  if( ioctl( bpf, BIOCSRTIMEOUT, &tv_timeout ) == -1 )
    {
      fprintf( stderr, "ERROR: BIOCGRTIMEOUT failed with errno = %i\n", errno );
      return( -1 );
    }
  
  printf( "- Timeout is set to %i seconds\n", timeout );
  return( buf_len );
}

// atoh(): Converts ASCII strings to hexadecimal values. Used to read MAC addresses
// from the command-line
int atoh( const char* src, char* target, unsigned int len )
{
  if( src == NULL ||
      target == NULL )
    {
      fprintf( stderr, "ERROR: atoh(): src and target mustn't be NULL\n" );
      return( -1 );
    }
  
  int c1 = 0;
  int c2 = 0;

  for( unsigned int i = 0; ( i < static_cast<unsigned int>( strlen( src ) ) ) && ( i < len * 2 ); i += 2 )
    {
      // check whether the numbers have to be converted

      c1 = tolower( src[ i ] );

      if( c1 >= '0' && c1 <= '9' )
	c1 -= '0';
      else if( c1 >= 'a' && c1 <= 'f' )
	c1 = c1 - 'a' + 10;
      else
	{
	  fprintf( stderr,
		   "ERROR: atoh(): '%c' is an invalid character (at pos %i)\n",
		   c1,
		   i );
	  return( -1 );
	}
	

      c2 = tolower( src[ i + 1 ] );
      
      if( c2 >= '0' && c2 <= '9' )
	c2 -= '0';
      else if( c2 >= 'a' && c2 <= 'f' )
	c2 = c2 - 'a' + 10;
      else
	{
	  fprintf( stderr,
		   "ERROR: atoh(): '%c' is an invalid character (at pos %i)\n",
		   c2,
		   i );
	  return( -1 );
	}
      
      // set the appropriate value

      target[ i / 2 ] = c1 * 16 + c2;
      
    }
  
  return( 0 );
}
