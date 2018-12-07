UCLA CS118 Fall18 Project 1 (Simple Router)
====================================

(For build dependencies, please refer to [`Vagrantfile`](Vagrantfile).)

## Makefile

The provided `Makefile` provides several targets, including to build `router` implementation.  The starter code includes only the framework to receive raw Ethernet frames and to send Ethernet frames to the desired interfaces.  Your job is to implement the routers logic.

Additionally, the `Makefile` a `clean` target, and `tarball` target to create the submission file as well.

You will need to modify the `Makefile` to add your userid for the `.tar.gz` turn-in at the top of the file.

## Academic Integrity Note

You are encouraged to host your code in private repositories on [GitHub](https://github.com/), [GitLab](https://gitlab.com), or other places.  At the same time, you are PROHIBITED to make your code for the class project public during the class or any time after the class.  If you do so, you will be violating academic honestly policy that you have signed, as well as the student code of conduct and be subject to serious sanctions.

## Known Limitations

When POX controller is restrated, the simpler router needs to be manually stopped and started again.

## Acknowledgement

This implementation is based on the original code for Stanford CS144 lab3 (https://bitbucket.org/cs144-1617/lab3).

## Project Report

My name is Michael Wu and my UID is 404751542.

In designing my solution, I first wrote helper functions to strip/replace the correct fields for Ethernet, ARP, and IP headers. This made it easy to process the incoming packets,
as I could easily construct response packets from the header structs. Then I verified the Ethernet header to determine if a frame needed to be processed by my router, and sent it
to the appropriate protocol. I discarded any frames that were not destined for my router or was not ARP or IPv4.

In processing ARP packets, I sent an ARP reply if an ARP request came and asked for the MAC address of my router's interface. If an ARP reply came then I cached the source MAC
address, then sent the queued up IP packets associated with the IP address in the ARP cache.

In processing IP packets, I first verified the length and checksum of the packet. I discarded any invalid packets. I also discarded the packets that had a destination at one of the
router's interfaces. Then I decremented TTL and recomputed the checksum to create a new IP header, looked at the routing table to find the next destination to sent to, and looked up
the MAC address of my destination. If the MAC Address is unknown I place the packet in the ARP Queue. If I know the MAC Address then I go ahead and create a new Ethernet header and
send the packet.

In order to successfully issue ARP requests, I implemented the periodicCheckArpRequestsAndCacheEntries() function in arp-cache.cpp. This function periodically sends out ARP requests
up to 5 times. It deletes any packets associated with an ARP request that is unanswered after 5 tries. I also implemented the lookup() function in routing-table.cpp. I used the longest
prefix match in order to decide between routes. This was implemented by using bit shifts to determine how long the mask was.

This implementation was basically exactly as described in the project description. Challenges I faced with implementation mainly dealt with converting from network byte order to host
order, as this involved a lot of casting and low level manipulations in order to see the bytes and bits that my program was operating on. I made a lot of print statements to standard error,
which I later removed in order to debug my program. This was a huge hassle and I could not think on a high level while I was doing this. I also had trouble computing the checksum because
of this. I was not aware that there was a helper function to compute the checksum already, so I implemented it myself with addition and bit shifts. I also abstracted away the process of
decoding/encoding headers in packets by writing functions to do this. Once I was able to do these things I simplified my code and made it easy to work with. The core logic of my code
was only about 150 or so lines, a lot of which was setting individual fields in the packets I wanted to send.

