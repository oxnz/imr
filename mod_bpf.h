//  mod_bpf.h -- prototypes to cope with the BPF

#ifndef IMR_MOD_BPF_H
#define IMR_MOD_BPF_H

int bpf_open( const char* interface );
int bpf_prepare( int bpf, unsigned int timeout );

int atoh( const char* src, char* target, unsigned int len );

#endif
