#ifndef _PKT_ETH_H_

#define _PKT_ETH_H_
#include "common.h"

static const size_t MACADDRLEN=6;
static const size_t MACTYPELEN=2;
class PacketEthernetII
{
public:
	PacketEthernetII(void) 
	{		
		memset(_packet, 0, 2*MACADDRLEN+MACTYPELEN * sizeof(*_packet));
		setPointers();
	};
	PacketEthernetII(const std::string& src, const std::string& dst,
		const std::string& type, const unsigned int radix);
	virtual ~PacketEthernetII(void){};
	void dst(const std::string& dst, const unsigned int radix)
	{
		Utilities::toBytes(dst, _macDst, MACADDRLEN, radix);		
	};
	unsigned char* dst(void)
	{
		return _macDst;
	};
	void src(const std::string& src, const unsigned int radix)
	{	
		Utilities::toBytes(src, _macSrc, MACADDRLEN, radix);		
	};
	unsigned char* src(void)
	{
		return _macSrc;
	};
	void type(const std::string& type, const unsigned int radix)
	{	
		Utilities::toBytes(type, _ethType, MACTYPELEN, radix);		
	};	
	unsigned char* type(void)
	{
		return _ethType;
	};
	unsigned char* packet(void)
	{
		return _packet;
	};
	unsigned int len(void)
	{
		return 2*MACADDRLEN+MACTYPELEN;
	};
private:
	PacketEthernetII(const PacketEthernetII&);
	void setPointers(void) {
		_macDst = _packet;
		_macSrc = _packet + MACADDRLEN;
		_ethType = _packet + 2 * MACADDRLEN;
	};
	unsigned char _packet[2*MACADDRLEN+MACTYPELEN];
	unsigned char* _macDst;
	unsigned char* _macSrc;
	unsigned char* _ethType;
};

#endif