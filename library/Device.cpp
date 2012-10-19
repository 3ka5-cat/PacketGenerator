#include "Device.h"

using namespace std;

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
		cerr << "Unable to open the adapter."
			<< _netInterface.name << " is not supported by WinPcap" << endl;         
        return;
    }
}

void Device::sendPacket(void)
{
	if (_netHandle == NULL)
		openInterface();
	u_char packet[100];
	/* Supposing to be on ethernet, set mac destination to 1:1:1:1:1:1 */
    packet[0]=1;
    packet[1]=1;
    packet[2]=1;
    packet[3]=1;
    packet[4]=1;
    packet[5]=1;
    
    /* set mac source to 2:2:2:2:2:2 */
    packet[6]=2;
    packet[7]=2;
    packet[8]=2;
    packet[9]=2;
    packet[10]=2;
    packet[11]=2;
    
    /* Fill the rest of the packet */
    for(int i=12;i<100;i++)
    {
        packet[i]=(u_char)i;
    }

    /* Send down the packet */
    if (pcap_sendpacket(_netHandle, packet, 100 /* size */) != 0)
    {
		cerr << "Error while sending the packet" << endl;        
		DbgMsg(__FILE__, __LINE__, 
			"pcap_sendpacket() ERROR %s\n", pcap_geterr(_netHandle));
        return;
    }
}