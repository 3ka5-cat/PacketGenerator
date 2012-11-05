#ifndef _PKT_ICMP_H_

#define _PKT_ICMP_H_
#include "common.h"
//#include "Packet.h"
namespace ICMP {
//Note! all lengths in bits
static LENGTH TYPELEN=8;
static LENGTH CODELEN=8;
static LENGTH CHECKSUMLEN=16;
static LENGTH IDLEN=16;
static LENGTH SEQLEN=16;

class PacketICMP
{
public:	
	PacketICMP(void)
	{
		_packet = new unsigned char[len()];
		memset(_packet, 0, len());
		setPointers();	
	};
	virtual ~PacketICMP(void)
	{
		delete[] _packet;
	};
	size_t len(void)
	{
		return (TYPELEN+CODELEN+
				CHECKSUMLEN+IDLEN+SEQLEN)>>3;
	};
	unsigned char* packet(void)
	{
		return _packet;
	};
	void type(const std::string& type, const unsigned int radix)
	{
		Utilities::toBytes(type, _type, TYPELEN>>3, radix);		
	};	
	void code(const std::string& code, const unsigned int radix)
	{
		Utilities::toBytes(code, _code, CODELEN>>3, radix);		
	};	
	void checksum(const std::string& checksum, const unsigned int radix)
	{
		Utilities::toBytes(checksum, _checksum, CHECKSUMLEN>>3, radix);		
	};
	void id(const std::string& id, const unsigned int radix)
	{
		Utilities::toBytes(id, _id, IDLEN>>3, radix);		
	};
	void seq(const std::string& seq, const unsigned int radix)
	{
		Utilities::toBytes(seq, _seq, SEQLEN>>3, radix);		
	};
private:
	PacketICMP(const PacketICMP&);
	void setPointers(void)
	{
		_type = _packet;
		_code = _type + (TYPELEN>>3);
		_checksum = _code + (CODELEN>>3);
		_id = _checksum + (CHECKSUMLEN>>3);
		_seq = _id + (IDLEN>>3);
	};
	unsigned char* _packet;
	unsigned char* _type;
	unsigned char* _code;
	unsigned char* _checksum;
	unsigned char* _id;
	unsigned char* _seq;
};
}
#endif