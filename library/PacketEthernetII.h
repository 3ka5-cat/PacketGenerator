#ifndef _PKT_ETH_H_

#define _PKT_ETH_H_
#include <cstdlib>
#include <algorithm>
#include "common.h"

static const unsigned int MACADDRLEN=6;
static const unsigned int MACTYPELEN=2;
class PacketEthernetII
{
public:
	PacketEthernetII(void) 
	{		
		memset(_packet, 0, 2*MACADDRLEN+MACTYPELEN * sizeof(*_packet));
		_macDst = _packet;
		_macSrc = _packet + MACADDRLEN;
		_ethType = _packet + 2 * MACADDRLEN;
	};
	PacketEthernetII(const char* src, const char* dst,
		const char* type);
	virtual ~PacketEthernetII(void){};
	void dst(const char* dst)
	{
		if (strlen(dst) != 2*MACADDRLEN)
			throw std::range_error("Incorrect destination MAC address length");
		Utilities::hex2bytes(dst,_macDst,MACADDRLEN);	
	};
	unsigned char* dst(void)
	{
		return _macDst;
	};
	void src(const char* src)
	{
		if (strlen(src) != 2*MACADDRLEN)
			throw std::range_error("Incorrect source MAC address length");
		Utilities::hex2bytes(src,_macSrc,MACADDRLEN);
	};
	unsigned char* src(void)
	{
		return _macSrc;
	};
	void type(const char* type)
	{
		if (strlen(type) != 2*MACTYPELEN)
			throw std::range_error("Incorrect Ethernet type length");
		Utilities::hex2bytes(type,_ethType,MACTYPELEN);	
	};	
	unsigned char* type(void)
	{
		return _ethType;
	};
	unsigned char* packet(void)
	{
		return _packet;
	};
	unsigned int packetLen(void)
	{
		return 2*MACADDRLEN+MACTYPELEN;
	};
private:
	PacketEthernetII(const PacketEthernetII&);
	unsigned char _packet[2*MACADDRLEN+MACTYPELEN];
	unsigned char* _macDst;
	unsigned char* _macSrc;
	unsigned char* _ethType;
};

#endif