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
	_netInterface(*pcap_if), eth(NULL), ip4(NULL), 
	icmp(NULL), tcp(NULL), udp(NULL)
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
	deletePacket();
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
		setGlobalError(string("Unable to open the adapter ").append(_netInterface.name));
		DbgMsg(__FILE__, __LINE__, 
			"Device::openInterface() pcap_open() ERROR: %s\n", errbuf);
        return;
    }
}

UDP::PacketUDP* Device::createUDP(const string& formatStr)
{
	TokenAndRadix src, dst, checksum, pktLen;
	if (!Utilities::parseUDPFormat(formatStr, src, 
		dst, checksum, pktLen)) {
			setGlobalError("Can't parse UDP format");
			DbgMsg(__FILE__, __LINE__, 
				"Device::createUDP() parseUDPFormat() ERROR: wrong format %s\n",
				formatStr.c_str());
			return NULL;
	}
	UDP::PacketUDP* udp;
	try{
		udp = new UDP::PacketUDP();
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
		setGlobalError(
			string("Can't create UDP packet with such parameters: ").append(e.what()));
		delete udp;
		return NULL;
	}
	return udp;
}

ICMP::PacketICMP* Device::createICMP(const string& formatStr)
{
	TokenAndRadix type, code, checksum, id, seq;
	if (!Utilities::parseICMPFormat(formatStr, type, 
		code, checksum, id, seq)) {
			setGlobalError("Can't parse ICMP format");
			DbgMsg(__FILE__, __LINE__, 
				"Device::createICMP() parseICMPFormat() ERROR: wrong format %s\n",
				formatStr.c_str());
			return NULL;
	}
	ICMP::PacketICMP* icmp;
	try{
		icmp = new ICMP::PacketICMP();
		icmp->type(type.token, type.radix);		
		icmp->code(code.token, code.radix);
		icmp->checksum(checksum.token, checksum.radix);
		icmp->id(id.token,id.radix);
		icmp->seq(seq.token,seq.radix);
	}
	catch (invalid_argument& e) {
		setGlobalError(
			string("Can't create ICMP packet with such parameters: ").append(e.what()));			 
		delete icmp;
		return NULL;
	}
	return icmp;
}

TCP::PacketTCP* Device::createTCP(const string& formatStr)
{	
	TokenAndRadix src, dst, seq, ack, offset, 
		reserved, flags, windowSize, checksum,
		urgentPointer;
	if (!Utilities::parseTCPFormat(formatStr, src, dst, seq, ack, offset, 
		reserved, flags, windowSize, checksum,
		urgentPointer)) {
			setGlobalError("Can't parse TCP format");
			DbgMsg(__FILE__, __LINE__, 
				"Device::createTCP() parseTCPFormat() ERROR: wrong format %s\n",
				formatStr.c_str());
			return NULL;
	}
	TCP::PacketTCP* tcp;
	try {
		tcp = new TCP::PacketTCP();
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
		setGlobalError(
			string("Can't create TCP packet with such parameters: ").append(e.what()));			 
		delete tcp;
		return NULL;
	}
	return tcp;
}

IPv4::PacketIPv4* Device::createIPv4(const string& formatStr)
{
	TokenAndRadix version, ihl, tos, pktLen, id, 
		flags, offset, ttl, protocol, hdrChecksum, 
		src, dst;
	if (!Utilities::parseIPv4Format(formatStr, version, 
		ihl, tos, pktLen, id, flags, offset, ttl, 
		protocol, hdrChecksum, src, dst)) {
			setGlobalError("Can't parse IPv4 format");
			DbgMsg(__FILE__, __LINE__, 
				"Device::createIPv4() parseIPv4Format() ERROR: wrong format %s\n",
				formatStr.c_str());
			return NULL;
	}
	IPv4::PacketIPv4* ip4;
	try {	
		ip4 = new IPv4::PacketIPv4();	
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
		setGlobalError(
			string("Can't create IPv4 packet with such parameters: ").append(e.what()));			 
		delete ip4;
		return NULL;
	}
	return ip4;
}

ETH2::PacketEthernetII* Device::createEthernet2(const string& formatStr)
{		
	TokenAndRadix src,dst,type;
	if (!Utilities::parseEthFormat(formatStr, src, dst, type)) {
		setGlobalError("Can't parse ETH2 format");
		DbgMsg(__FILE__, __LINE__, 
			"Device::createEthernet2() parseEthFormat() ERROR: wrong format %s\n",
			formatStr.c_str());		
		return NULL;
	}
	ETH2::PacketEthernetII* eth;
	try {
		eth = new ETH2::PacketEthernetII();	
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
		setGlobalError(
			string("Can't create EthernetII packet with such parameters: ").append(e.what()));
		delete eth;
		return NULL;
	}	
	return eth;
}

bool Device::buildPackets(const Tokens& formats, bool validateOnly)
{
	packetLen = 0;
	bool transport = false;
	for (size_t i = 0; i < formats.size(); ++i) {
		DbgMsg(__FILE__, __LINE__,
			"%u format: %s\n", i, formats[i].c_str());
		if (Utilities::startsWith(formats[i], ETH2PROTO)) {			
			if (eth)
				delete eth;
			//ETH2:src,radix;dst,radix;type,radix
			eth = createEthernet2(formats[i]);
			//"ETH2:000C29F2178F,16;DCA97150BDBA,16;0800,16;");
			if (!eth) {
				deletePacket();
				return false;			
			}
			packetLen += eth->len();			
		}
		else if (Utilities::startsWith(formats[i], IPV4PROTO)) {				
			//IPv4:version,radix;ihl,radix;tos,radix;pktLen,radix;id,radix;flags,radix;
			//offset,radix;ttl,radix;protocol,radix;hdrChecksum,radix;src,radix;dst,radix;
			if (ip4)
				delete ip4;
			ip4 = createIPv4(formats[i]);
			//"IPv4:4,10;5,10;65530,10;40,10;1,10;7,10;0,10;FF,16;1,10;AABB,16;3232235616,10;3232252803,10;"
			if (!ip4) {
				deletePacket();
				return false;	
			}
			packetLen += ip4->len();
		}
		else if (Utilities::startsWith(formats[i], UDPPROTO)) {
			if (!transport) {
				transport = true;
				//UDP:src,radix;dst,radix;checksum,radix;pktLen,radix;
				if (udp)
					delete udp;
				udp = createUDP(formats[i]);
				//"UDP:17500,10;17500,10;CF75,16;8,10;"
				if (!udp) {
					deletePacket();
					return false;	
				}
				packetLen += udp->len();
			}
			else {
				setGlobalError("Several transport layer protocols");
				DbgMsg(__FILE__, __LINE__, 
					"Device::buildPackets() ERROR: several transport layer protocols\n");	
				deletePacket();
				return false;			
			}
		}
		else if (Utilities::startsWith(formats[i], TCPPROTO)) {	
			if (!transport) {
				transport = true;
				if (tcp)
					delete tcp;
				//TCP:src,radix;dst,radix;seq,radix;ack,radix;offset,radix;reserved,radix;flags,radix;windowSize,radix;checksum,radix;urgentPointer,radix;
				tcp = createTCP(formats[i]);
				//"TCP:80,10;5754,10;EFA88B77,16;9E6393BF,16;5,10;0,10;0,10;93,10;942B,16;0,10;"
				if (!tcp) {
					deletePacket();
					return false;	
				}
				packetLen += tcp->len();
			}
			else {
				setGlobalError("Several transport layer protocols");
				DbgMsg(__FILE__, __LINE__, 
					"Device::buildPackets() ERROR: several transport layer protocols\n");	
				deletePacket();
				return false;			
			}
		}
		else if (Utilities::startsWith(formats[i], ICMPPROTO)) {	
			if (!transport) {
				transport = true;
				if (icmp)
					delete icmp;
				//ICMP:type,radix;code,radix;checksum,radix;id,radix;seq,radix;
				icmp = createICMP(formats[i]);
				//"ICMP:0,10;0,10;CF75,16;1,10;1,10;"
				if (!icmp) {
					deletePacket();
					return false;	
				}
				packetLen += icmp->len();
			}
			else {
				setGlobalError("Several transport layer protocols");
				DbgMsg(__FILE__, __LINE__, 
					"Device::buildPackets() ERROR: several transport layer protocols\n");	
				deletePacket();
				return false;			
			}
		}
	}	
	if (packetLen) {
		if (validateOnly)
			deletePacket();
		return true;
	}
	else { 
		setGlobalError("Empty formats");
		return false;
	}
}

void Device::deletePacket(void)
{
	packetLen = 0;
	delete eth;
	delete ip4;
	delete udp;
	delete tcp;
	delete icmp;
	eth = NULL;
	ip4 = NULL;
	udp = NULL;
	tcp = NULL;
	icmp = NULL;
}

void Device::sendPacket(const Tokens& formats, unsigned int count)
{	
	if (!_netHandle)
		openInterface();		
	//unsigned int data = 0xffffffff;
	if (packetLen > 0 && packetLen < 65535) {
		u_char* packet = new u_char[packetLen];
		if (eth)
			memcpy(packet, eth->packet(), eth->len());
		if (ip4)
			memcpy(packet + eth->len(), ip4->packet(), ip4->len());	
		if (tcp)
			memcpy(packet + eth->len() + ip4->len(), tcp->packet(), tcp->len());
		if (icmp)
			memcpy(packet + eth->len() + ip4->len(), icmp->packet(), icmp->len());
		if (udp)
			memcpy(packet + eth->len() + ip4->len(), udp->packet(), udp->len());
		//memcpy(packet + eth->len() + ip4->len() + udp->len(), &data, sizeof(unsigned int));
		if (pcap_sendpacket(_netHandle, packet, packetLen) != 0) {
				setGlobalError("Error while sending the packet");        
				DbgMsg(__FILE__, __LINE__, 
					"Device::sendPacket() pcap_sendpacket() ERROR: %s\n", pcap_geterr(_netHandle));			
		}	
		delete[] packet;
	}
	else {
		setGlobalError("Error while sending the packet: packet is empty");        
		DbgMsg(__FILE__, __LINE__, 
			"Device::sendPacket() ERROR: packet wasn't initialized\n");		
	}

}