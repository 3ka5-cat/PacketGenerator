#ifndef _DEVICE_H_

#define _DEVICE_H_

#include "common.h"
#include "PacketEthernetII.h"
#include "PacketIPv4.h"
#include "PacketUDP.h"
#include "PacketTCP.h"
#include "PacketICMP.h"

#include <string>
#include <vector>

struct interfaceAddress {
	std::string family;
	std::string address;
	std::string netmask;
	std::string broadAddress;
};
typedef std::vector<interfaceAddress> InterfaceAddresses;

// From tcptraceroute, convert a numeric IP address to a string 
static const unsigned int IPTOSBUFFERS=12;

class Device
{
public:
	Device(pcap_if_t* pcap_if);
	virtual ~Device(void);
	std::string name(void)
	{
		return _name;
	};
	std::string description(void)
	{
		return _description;
	};
	InterfaceAddresses& addresses(void)
	{
		return _addresses;
	};
	bool loopback(void)
	{
		return _loopback;
	};
	bool buildPackets(const Tokens& formats, bool validateOnly = false);	
	void sendPacket(const Tokens& formats, unsigned int count = -1);
private:
	Device(const Device&);
	void deletePacket(void);
	IPv4::PacketIPv4* createIPv4(const std::string& formatStr);
	UDP::PacketUDP* createUDP(const std::string& formatStr);
	TCP::PacketTCP* createTCP(const std::string& formatStr);
	ETH2::PacketEthernetII* createEthernet2(const std::string& formatStr);
	ICMP::PacketICMP* createICMP(const std::string& formatStr);
	char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
	char* iptos(u_long in);
	void openInterface(void);
	pcap_if_t _netInterface;
	pcap_t* _netHandle;
	
	std::string _name;
	std::string _description;
	bool _loopback;
	InterfaceAddresses _addresses;	


	size_t packetLen;
	ETH2::PacketEthernetII* eth;	
	IPv4::PacketIPv4* ip4;	
	ICMP::PacketICMP* icmp;
	TCP::PacketTCP* tcp;
	UDP::PacketUDP* udp;
};

#endif