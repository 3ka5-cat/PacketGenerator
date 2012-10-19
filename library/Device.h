#ifndef _DEVICE_H_

#define _DEVICE_H_
#include "common.h"

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
	void sendPacket(void);
private:
	Device(const Device&);
	char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
	char* iptos(u_long in);
	void openInterface(void);
	pcap_if_t _netInterface;
	pcap_t* _netHandle;
	
	std::string _name;
	std::string _description;
	bool _loopback;
	InterfaceAddresses _addresses;	
};

#endif