#include "Device.h"

using namespace std;
using namespace ETH2;
using namespace IPv4;
using namespace UDP;
using namespace TCP;
using namespace ICMP;

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
			"Device::openInterface() pcap_open() ERROR: %s\n", errbuf);
        return;
    }
}

PacketUDP* Device::createUDP(const string& formatStr)
{
	TokenAndRadix src, dst, checksum, pktLen;
	if (!Utilities::parseUDPFormat(formatStr, src, 
		dst, checksum, pktLen)) {
			cerr << "Can't parse UDP format" << endl;
			return NULL;
	}
	PacketUDP* udp;
	try{
		udp = new PacketUDP();
		udp->srcPort(src.token, src.radix);		
		udp->dstPort(dst.token, dst.radix);
		udp->checksum(checksum.token, checksum.radix);
		udp->pktLen(pktLen.token,pktLen.radix);
		/*
		udp->srcPort("17500",10);		
		udp->dstPort("17500",10);
		udp->checksum("CF75", 16);
		udp->pktLen("8", 10);	
		*/
	}
	catch (invalid_argument& e) {
		cerr << "Can't create UDP packet with such parameters: " << endl 
			 << e.what() << endl;
		delete udp;
		return NULL;
	}
	return udp;
}

PacketICMP* Device::createICMP(const string& formatStr)
{
	TokenAndRadix type, code, checksum, id, seq;
	if (!Utilities::parseICMPFormat(formatStr, type, 
		code, checksum, id, seq)) {
			cerr << "Can't parse ICMP format" << endl;
			return NULL;
	}
	PacketICMP* icmp;
	try{
		icmp = new PacketICMP();
		icmp->type(type.token, type.radix);		
		icmp->code(code.token, code.radix);
		icmp->checksum(checksum.token, checksum.radix);
		icmp->id(id.token,id.radix);
		icmp->seq(seq.token,seq.radix);
	}
	catch (invalid_argument& e) {
		cerr << "Can't create ICMP packet with such parameters: " << endl 
			 << e.what() << endl;
		delete icmp;
		return NULL;
	}
	return icmp;
}

PacketTCP* Device::createTCP(const string& formatStr)
{	
	TokenAndRadix src, dst, seq, ack, offset, 
		reserved, flags, windowSize, checksum,
		urgentPointer;
	if (!Utilities::parseTCPFormat(formatStr, src, dst, seq, ack, offset, 
		reserved, flags, windowSize, checksum,
		urgentPointer)) {
			cerr << "Can't parse TCP format" << endl;
		return NULL;
	}
	PacketTCP* tcp;
	try {
		tcp = new PacketTCP();
		tcp->srcPort(src.token,src.radix);
		tcp->dstPort(dst.token,dst.radix);
		tcp->seq(seq.token,seq.radix);
		tcp->ack(ack.token,ack.radix);
		tcp->offset(offset.token,offset.radix);
		tcp->reserved(reserved.token,reserved.radix);
		tcp->flags(flags.token,flags.radix);		
		tcp->windowSize(windowSize.token,windowSize.radix);
		tcp->checksum(checksum.token,checksum.radix);
		tcp->urgentPointer(checksum.token,checksum.radix);
		/*
		tcp->srcPort("80",10);
		tcp->dstPort("52754",10);
		tcp->seq("EFA88B77",16);
		tcp->ack("9E6393BF",16);
		tcp->offset("5",10);
		tcp->reserved("0",10);
		tcp->flags("0",10);
		tcp->finFlag(true);
		tcp->ackFlag(true);
		tcp->pshFlag(true);
		tcp->rstFlag(true);
		tcp->synFlag(true);
		tcp->urgFlag(true);
		tcp->windowSize("93",10);
		tcp->checksum("942B",16);
		tcp->urgentPointer("0",10);
		*/
	}
	catch (invalid_argument& e) {
		cerr << "Can't create TCP packet with such parameters: " << endl 
			 << e.what() << endl;
		delete tcp;
		return NULL;
	}
	return tcp;
}

PacketIPv4* Device::createIPv4(const string& formatStr)
{
	TokenAndRadix version, ihl, tos, pktLen, id, 
		flags, offset, ttl, protocol, hdrChecksum, 
		src, dst;
	if (!Utilities::parseIPv4Format(formatStr, version, 
		ihl, tos, pktLen, id, flags, offset, ttl, 
		protocol, hdrChecksum, src, dst)) {
			cerr << "Can't parse IPv4 format" << endl;
			return NULL;
	}
	PacketIPv4* ip4;
	try {	
		ip4 = new PacketIPv4();	
		ip4->version(version.token, version.radix);		
		ip4->ihl(ihl.token,ihl.radix);				
		ip4->tos(tos.token,tos.radix);		
		ip4->pktLen(pktLen.token,pktLen.radix);
		ip4->id(id.token,id.radix);
		ip4->flags(flags.token, flags.radix);		
		ip4->offset(offset.token,offset.radix);		
		ip4->ttl(ttl.token,ttl.radix);
		ip4->protocol(protocol.token,protocol.radix);
		ip4->hdrChecksum(hdrChecksum.token,hdrChecksum.radix);		
		ip4->src(src.token,src.radix);
		ip4->dst(dst.token,dst.radix);
		/*
		ip4->version("4", 10);		
		ip4->ihl("5",10);		
		ip4->priorityTos("0",10);
		ip4->delayTos(false);
		ip4->throughputTos(false);
		ip4->reliabilityTos(false);		
		ip4->ecnTos("0",10);		
		ip4->pktLen("40",10);
		ip4->id("1",10);
		ip4->reservedFlag(false);
		ip4->dfFlag(false);		
		ip4->mfFlag(false);		
		ip4->offset("0",10);		
		ip4->ttl("FF",16);
		ip4->protocol("6",10);
		ip4->hdrChecksum("AABB",16);		
		ip4->src("3232235616",10);
		ip4->dst("3232252803",10);
		*/
	}
	catch (invalid_argument& e) {
		cerr << "Can't create IPv4 packet with such parameters: " << endl 
			 << e.what() << endl;
		delete ip4;
		return NULL;
	}
	return ip4;
}

PacketEthernetII* Device::createEthernet2(const string& formatStr)
{		
	TokenAndRadix src,dst,type;
	if (!Utilities::parseEthFormat(formatStr, src, dst, type)) {
		cerr << "Can't parse ETH2 format" << endl;
		return NULL;
	}
	PacketEthernetII* eth;
	try {
		eth = new PacketEthernetII();	
		/*
		eth->dst("000C29F2178F",16);
		eth->src("DCA97150BDBA",16);
		eth->type("0800", 16);
		*/
		eth->dst(dst.token,dst.radix);
		eth->src(src.token,src.radix);
		eth->type(type.token,type.radix);
	}
	catch (invalid_argument& e) {
		cerr << "Can't create EthernetII packet with such parameters: " << endl 
			 << e.what() << endl;
		delete eth;
		return NULL;
	}	
	return eth;
}

void Device::sendPacket(void)
{
	if (!_netHandle)
		openInterface();

	//UDP:src,radix>dst,radix;checksum,radix;pktLen,radix;
	PacketUDP* udp = createUDP("UDP:17500,10>17500,10;CF75,16;8,10;");
	if (!udp)
		return;
	//TCP:src,radix>dst,radix;seq,radix;ack,radix;offset,radix;reserved,radix;flags,radix;windowSize,radix;checksum,radix;urgentPointer,radix;
	PacketTCP* tcp = createTCP("TCP:80,10>5754,10;EFA88B77,16;9E6393BF,16;5,10;0,10;0,10;93,10;942B,16;0,10;");
	if (!tcp)
		return;
	//ICMP:type,radix;code,radix;checksum,radix;id,radix;seq,radix;
	PacketICMP* icmp = createICMP("ICMP:0,10;0,10;CF75,16;1,10;1,10;");
	if (!icmp)
		return;
	//IPv4:version,radix;ihl,radix;tos,radix;pktLen,radix;id,radix;flags,radix;
	//offset,radix;ttl,radix;protocol,radix;hdrChecksum,radix;src,radix;dst,radix;
	PacketIPv4* ip4 = createIPv4("IPv4:4,10;5,10;65530,10;40,10;1,10;7,10;0,10;FF,16;1,10;AABB,16;3232235616,10;3232252803,10;");
	if (!ip4)
		return;
	//ETH2:src,radix>dst,radix;type,radix
	PacketEthernetII* eth = createEthernet2(
		"ETH2:000C29F2178F,16>DCA97150BDBA,16;0800,16;");
	if (!eth)
		return;	

	const size_t packetLen = eth->len() + ip4->len() + icmp->len();
	//const size_t packetLen = eth->len() + ip4->len() + tcp->len();
	//const size_t packetLen = eth->len() + ip4->len() + udp->len();	
	//unsigned int data = 0xffffffff;
	u_char* packet = new u_char[packetLen];
	memcpy(packet, eth->packet(), eth->len());
	memcpy(packet + eth->len(), ip4->packet(), ip4->len());	
	memcpy(packet + eth->len() + ip4->len(), icmp->packet(), icmp->len());
	//memcpy(packet + eth->len() + ip4->len(), tcp->packet(), tcp->len());
	//memcpy(packet + eth->len() + ip4->len(), udp->packet(), udp->len());
	//memcpy(packet + eth->len() + ip4->len() + udp->len(), &data, sizeof(unsigned int));

    if (pcap_sendpacket(_netHandle, packet, packetLen) != 0) {
		cerr << "Error while sending the packet" << endl;        
		DbgMsg(__FILE__, __LINE__, 
			"Device::sendPacket() pcap_sendpacket() ERROR: %s\n", pcap_geterr(_netHandle));
		delete packet;
		delete eth;
		delete ip4;
		delete udp;
		delete tcp;
		delete icmp;
        return;
    }
	delete packet;
	delete eth;
	delete ip4;
	delete udp;
	delete tcp;
	delete icmp;
}