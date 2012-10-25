#ifndef _PKT_IP4_H_

#define _PKT_IP4_H_
#include "common.h"
namespace IPv4 {
//Note! all lengths in bits
static LENGTH VERLEN=4;
static LENGTH IHLLEN=4;
static LENGTH VERIHLLEN=VERLEN+IHLLEN;
static LENGTH TOSLEN=8;
static LENGTH PKTLENLEN=16;
static LENGTH IDLEN=16;
static LENGTH FLAGSLEN=3;
static LENGTH OFFSETLEN=13;
static LENGTH FLAGSOFFSETLEN=FLAGSLEN+OFFSETLEN;
static LENGTH TTLLEN=8;
static LENGTH PROTOCOLLEN=8;
static LENGTH HEADERCHECKSUMLEN=16;
static LENGTH IPADDRESSLEN=32;

// bit masks, network order
static MASK VERSION = 0xF0;
static MASK IHL = 0xF;

static MASK PRIORITYTOS = 0xE0;
static MASK DELAYTOS = 0x10;
static MASK THROUGHPUTTOS = 0x8;
static MASK RELIABILITYTOS = 0x4;
static MASK ECNTOS = 0x3;

static MASK RESERVEDFLAG = 0x80;
static MASK DFFLAG = 0x40;
static MASK MFFLAG = 0x20;
static MASK OFFSET = 0x1F;


class PacketIPv4
{
public:
	PacketIPv4(void)
	{
		_packet = new unsigned char[len()];
		memset(_packet,0,len());
		setPointers();	
	};
	virtual ~PacketIPv4(void){ 
		delete[] _packet;
	};

	void version(const unsigned char& version)	
	{		
		*_verIhl |= (version << 4) & VERSION;		
	};
	void ihl(const unsigned char& ihl)
	{		
		*_verIhl |= ihl & IHL; 		
	};

	void tos(const std::string& tos, const unsigned int radix)
	{
		Utilities::toBytes(tos, _tos, TOSLEN>>3, radix);				
	};	
	void priorityTos(const std::string& priority, const unsigned int radix)
	{
		unsigned char _priority = 0;
		Utilities::toBytes(priority, &_priority, 0, radix,3);
		*_tos |= (_priority << 6) & PRIORITYTOS;				
	};		
	void delayTos(const bool delay)
	{		
		delay ? *_tos |= DELAYTOS : *_tos &= ~DELAYTOS;				
	};		
	void throughputTos(const bool throughput)
	{
		throughput ? *_tos |= THROUGHPUTTOS : *_tos &= ~THROUGHPUTTOS;				
	};	
	void reliabilityTos(const bool reliability)
	{
		reliability ? *_tos |= RELIABILITYTOS : *_tos &= ~RELIABILITYTOS;				
	};	
	void ecnTos(const std::string& ecn, const unsigned int radix)
	{
		unsigned char _ecn = 0;
		Utilities::toBytes(ecn, &_ecn, 0, radix,2);
		*_tos |= _ecn & ECNTOS;				
	};	

	void pktLen(const std::string& pktLen, const unsigned int radix)
	{
		Utilities::toBytes(pktLen, _pktLen, PKTLENLEN>>3, radix);		
	};	

	void id(const std::string& id, const unsigned int radix)
	{
		Utilities::toBytes(id, _id, IDLEN>>3, radix);		
	};	

	void flags(const std::string& flags, const unsigned int radix)
	{
		unsigned char _flags = 0;	// 3 bit
		Utilities::toBytes(flags, &_flags, 0, radix, FLAGSLEN);	
		//network order
		*_flagsOffset |= (_flags << 5) & (RESERVEDFLAG | DFFLAG | MFFLAG);		
	};
	void reservedFlag(const bool reserved)
	{
		reserved ? *_flagsOffset |= RESERVEDFLAG : 
			*_flagsOffset &= ~RESERVEDFLAG;				
	};
	void dfFlag(const bool df)
	{
		df ? *_flagsOffset |= DFFLAG : 
			*_flagsOffset &= ~DFFLAG;				
	};
	void mfFlag(const bool mf)
	{
		mf ? *_flagsOffset |= MFFLAG : 
			*_flagsOffset &= ~MFFLAG;				
	};

	void offset(const std::string& offset, const unsigned int radix)
	{
		unsigned char _offset[2];	// 13 bit
		Utilities::toBytes(offset, _offset, 0, radix, OFFSETLEN);	
		//network order
		*_flagsOffset |= (_offset[1] >> 4) & OFFSET;
		*(_flagsOffset+1) |= _offset[0];

		//unsigned short hostFlagsOffset = ntohs(*_flagsOffset);	
		//hostFlagsOffset |= _offset & 0x1FFF;
		//*_flagsOffset = htons(hostFlagsOffset);		
	};

	void ttl(const std::string& ttl, const unsigned int radix)
	{
		Utilities::toBytes(ttl, _ttl, 1, radix);		
	};	

	void protocol(const std::string& protocol, const unsigned int radix)
	{
		Utilities::toBytes(protocol, _protocol, PROTOCOLLEN>>3, radix);		
	};	

	void hdrChecksum(const std::string& hdrChecksum, const unsigned int radix)
	{
		Utilities::toBytes(hdrChecksum, _hdrChecksum, HEADERCHECKSUMLEN>>3, radix);		
	};	

	void src(const std::string& src, const unsigned int radix)
	{
		Utilities::toBytes(src, _ipSrc, IPADDRESSLEN>>3, radix);		
	};	

	void dst(const std::string& dst, const unsigned int radix)
	{
		Utilities::toBytes(dst, _ipDst, IPADDRESSLEN>>3, radix);		
	};	

	unsigned char* packet(void)
	{
		return _packet;
	};

	size_t len(void)
	{
		return (VERIHLLEN+TOSLEN+PKTLENLEN+
				IDLEN+FLAGSOFFSETLEN+
				TTLLEN+PROTOCOLLEN+
				HEADERCHECKSUMLEN+
				2*IPADDRESSLEN)>>3;
	};

private:
	PacketIPv4(const PacketIPv4&);
	void setPointers(void)
	{
		_verIhl = _packet;
		_tos = _verIhl + (VERIHLLEN>>3);
		_pktLen = _tos + (TOSLEN>>3);
		_id = _pktLen + (PKTLENLEN>>3);
		_flagsOffset = _id + (IDLEN>>3);	
		_ttl = _flagsOffset + (FLAGSOFFSETLEN>>3);
		_protocol = _ttl + (TTLLEN>>3);
		_hdrChecksum = _protocol + (PROTOCOLLEN>>3);
		_ipSrc = _hdrChecksum + (HEADERCHECKSUMLEN>>3);
		_ipDst = _ipSrc + (IPADDRESSLEN>>3);
	};
		
	unsigned char* _packet;
	unsigned char* _verIhl;
	unsigned char* _tos;
	unsigned char* _pktLen;
	unsigned char* _id;
	unsigned char* _flagsOffset;
	unsigned char* _ttl;
	unsigned char* _protocol;
	unsigned char* _hdrChecksum;
	unsigned char* _ipSrc;
	unsigned char* _ipDst;
	//TODO: params and data
};
}

#endif