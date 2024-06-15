This PoC simulates a  reflected DDos by sending packets to published turn servers with the target server's address as the source. 
It causes the list of servers (cidr_list) to respond to the target server's requests from the subnets of the published servers (i.e. signal,zoom,facebook,google,etc...)


To compile simply run 
``` g++  raw_sender.cpp -o raw ```



Usage:  ./raw target connection_name target6 


- target : IPv4 target
- connection_name: NIC (en0,eth0,docker0,etc...)
- target6: IPv6 address to relay IPv4 src packets, if empty it is collected from the network (might take some time)
  

It requires super user to permissions to read/write raw sockets.


Use responsibly.
<3

