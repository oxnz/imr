#IMR

an ARP table attack program, original written by Bastian Rieck, modified and improved by oxnz.

##DESCRIPTION

IMR gives you the ability to check whether your network is secured
against ARP attacks. Furthermore, it allows you to analyze networking
protocols in great detail without changing data.

##HOW IT WORKS

This is what IMR does:

###Send (forged) ARP replies
Two ARP replies of the form 'a.b.c.d is at AB:CD:EF:GH' are
sent to both the client and the server, hence ensuring that
both hosts consider this PC the current communication
partner.

###Read data
Now all incoming data is read. A loop checks whether they
originate from the client or from the server. During this
check, the destination address of the current Ethernet frame
is set to the proper MAC address, so that the packets don't
get stuck.

###Log data
Everything is logged in raw format, i.e. each packet plus
all of its payload is written to the disk. The log file does
not look good, but it will allow a complete reconstruction
of each packet.

###Reset the ARP tables
After the routing has been cancelled, two ARP replies are
sent that restore the ARP table, so that the proper MAC
addresses are set.

##WHY IT WORKS

To work properly, ARP needs an ARP table, in which pairs of MAC
addresses and IP addresses are saved. This is why your kernel 'knows'
the destination address of the Ethernet frame. Unfortunately, ARP
doesn't check whether packets have been requested or not. So you are
able to poison the ARP table by sending your own ARP replies that say
something like 'You will find this IP address at my MAC address'. There
is no possibility for ARP to validate your MAC address / IP address
pair, so it will be added to the table.

##LICNESE
GPL

