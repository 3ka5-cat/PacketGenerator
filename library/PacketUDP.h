#ifndef _PKT_UDP_H_

#define _PKT_UDP_H_
#include "common.h"
//#include "Packet.h"
namespace UDP {
//Note! all lengths in bits
static LENGTH PORTLEN=16;
static LENGTH PKTLENLEN=16;
static LENGTH CHECKSUMLEN=16;

class PacketUDP //: Packet
{
public:	
	PacketUDP(void)
	{
		_packet = new unsigned char[len()];
		memset(_packet, 0, len());
		setPointers();	
	};
	virtual ~PacketUDP(void)
	{
		delete[] _packet;
	}
	size_t len(void)
	{
		return (2*PORTLEN+PKTLENLEN+
				CHECKSUMLEN)>>3;
	};
	void srcPort(const std::string& src, const unsigned int radix)
	{
		Utilities::toBytes(src, _srcPort, PORTLEN>>3, radix);		
	};	
	void dstPort(const std::string& dst, const unsigned int radix)
	{
		Utilities::toBytes(dst, _dstPort, PORTLEN>>3, radix);		
	};
	void pktLen(const std::string& pktLen, const unsigned int radix)
	{
		Utilities::toBytes(pktLen, _pktLen, PKTLENLEN>>3, radix);		
	};	
	void checksum(const std::string& checksum, const unsigned int radix)
	{
		Utilities::toBytes(checksum, _checksum, CHECKSUMLEN>>3, radix);		
	};	
	unsigned char* packet(void)
	{
		return _packet;
	};
private:
	PacketUDP(const PacketUDP&);
	void setPointers(void)
	{
		_srcPort = _packet;
		_dstPort = _srcPort + (PORTLEN>>3);
		_pktLen = _dstPort + (PORTLEN>>3);
		_checksum = _pktLen + (PKTLENLEN>>3);
	};
	unsigned char* _packet;
	unsigned char* _srcPort;
	unsigned char* _dstPort;
	unsigned char* _pktLen;
	unsigned char* _checksum;	
};
}
#endif

