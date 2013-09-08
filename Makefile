all: imr.o mod_bpf.o mod_eth.o mod_arp.o
	g++ *.o -o imr

imr.o: imr.cpp
	g++ -c imr.cpp

mod_bpf.o: mod_bpf.cpp
	g++ -c mod_bpf.cpp

mod_eth.o: mod_eth.cpp
	g++ -c mod_eth.cpp

mod_arp.o: mod_arp.cpp
	g++ -c mod_arp.cpp
	
clean:
	-rm *~ *.o *.core
