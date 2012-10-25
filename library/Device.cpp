#include "Device.h"

using namespace std;
using namespace IPv4;

char* Device::iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    _snprintf_s(output[which], sizeof(output[which]), 
		sizeof(output[which]),"%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

char* Device::ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

    #ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
    #else
    sockaddrlen = sizeof(struct sockaddr_storage);
    #endif
	
    if(getnameinfo(sockaddr, 
        sockaddrlen, 
        address, 
        addrlen, 
        NULL, 
        0, 
        NI_NUMERICHOST) != 0) address = NULL;

    return address;
}


Device::Device(pcap_if_t* pcap_if) : _netHandle(NULL), 
	_netInterface(*pcap_if)
{	
	_name = _netInterface.name;
	if (_netInterface.description)
			_description = _netInterface.description;		
	else
		_description = "(No description available)";
	_loopback = (_netInterface.flags & PCAP_IF_LOOPBACK) ? true : false;

	for(pcap_addr_t *a = _netInterface.addresses; a ; a = a->next) {
		interfaceAddress addr;
		switch(a->addr->sa_family) {
			case AF_INET:				
				addr.family = "IPv4";
				if (a->addr)
					addr.address = iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);          
				if (a->netmask)
					addr.netmask = iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);                    
				if (a->broadaddr)
					addr.broadAddress = iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr);         				
				break;
			case AF_INET6:
				addr.family = "IPv6";        
				if (a->addr) {
					char ip6str[128];
					addr.address = ip6tos(a->addr, ip6str, sizeof(ip6str)); 
					addr.netmask = "empty";
					addr.broadAddress = "empty";					
				}
				break;
			default:
				addr.family = "Unknown"; 
				addr.address = "Unknown";
				addr.netmask = "Unknown";
				addr.broadAddress = "Unknown";
				break;
		}
		_addresses.push_back(addr);
	}
	
}

Device::~Device(void)
{
}

void Device::openInterface(void)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	/* Open the output device*/ 
    if ((_netHandle = pcap_open(_netInterface.name, // name of the device
                        0,					// portion of the packet to capture
                        NULL,				// flags
                        NULL,               // read timeout
                        NULL,               // authentication on the remote machine
                        errbuf              // error buffer
                        )) == NULL)
    {
		cerr << "Unable to open the adapter " 
			<< _netInterface.name << endl; 
		DbgMsg(__FILE__, __LINE__, 
			"pcap_open() ERROR: %s\n", errbuf);
        return;
    }
}

void Device::sendPacket(void)
{
	
	unsigned char n = 170;
	for (int k=0; k < 8; ++k) {		
		unsigned char thebit = (n & (1 << k)) >> k;
		printf("");
	}
	
	if (_netHandle == NULL)
		openInterface();
	PacketEthernetII* eth;
	try {
		eth = new PacketEthernetII();		
		eth->dst("000C29F2178F",16);
		eth->src("DCA97150BDBA",16);
		eth->type("0800", 16);
	}
	catch (invalid_argument& e) {
		cerr << "Can't create EthernetII packet with such parameters: " << endl 
			 << e.what() << endl;
		return;
	}
	PacketIPv4* ip4;	
	try {	
		ip4 = new PacketIPv4();	
		//TODO: split string to byte conversation from packets logic maybe?
		unsigned char version = 0;
		Utilities::toBytes("4", &version, 0, 10, VERLEN);
		ip4->version(version);
		unsigned char ihl = 0;
		Utilities::toBytes("5", &ihl, 0, 10, IHLLEN);
		ip4->ihl(ihl);		
		ip4->priorityTos("0",10);
		ip4->delayTos(false);
		ip4->throughputTos(false);
		ip4->reliabilityTos(false);		
		ip4->ecnTos("0",10);		
		ip4->pktLen("20",10);
		ip4->id("1",10);
		ip4->reservedFlag(false);
		ip4->dfFlag(false);		
		ip4->mfFlag(false);		
		ip4->offset("0",10);		
		ip4->ttl("FF",16);
		ip4->protocol("1",10);
		ip4->hdrChecksum("AABB",16);		
		ip4->src("3232235616",10);
		ip4->dst("3232252803",10);
	}
	catch (invalid_argument& e) {
		cerr << "Can't create IPv4 packet with such parameters: " << endl 
			 << e.what() << endl;
		return;
	}

	const size_t packetLen = eth->len() + ip4->len();	
	u_char* packet = new u_char[packetLen];
	memcpy(packet, eth->packet(), eth->len());
	memcpy(packet + eth->len(), ip4->packet(), ip4->len());

    if (pcap_sendpacket(_netHandle, packet, packetLen) != 0)
    {
		cerr << "Error while sending the packet" << endl;        
		DbgMsg(__FILE__, __LINE__, 
			"pcap_sendpacket() ERROR: %s\n", pcap_geterr(_netHandle));
		delete packet;
		delete eth;
        return;
    }
	delete packet;
	delete eth;
}