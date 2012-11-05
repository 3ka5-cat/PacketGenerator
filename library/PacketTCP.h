#ifndef _PKT_TCP_H_

#define _PKT_TCP_H_
#include "common.h"

namespace TCP {
//Note! all lengths in bits
static LENGTH PORTLEN=16;
static LENGTH SEQLEN=32;
static LENGTH ACKLEN=32;
static LENGTH OFFSETLEN=4;
static LENGTH RESERVEDLEN=6;
static LENGTH FLAGLEN=6;
static LENGTH OFFSRESFLAGSLEN=OFFSETLEN+RESERVEDLEN+FLAGLEN;
static LENGTH WINDOWSIZELEN=16;
static LENGTH CHECKSUMLEN=16;
static LENGTH URGENTPOINTERLEN=16;

// bit masks, network order
static MASK OFFSET = 0xF0;
static MASK RESERVED = 0xE;
static MASK FLAGS = 0x3F;

static MASK FINFLAG = 0x1;
static MASK SYNFLAG = 0x2;
static MASK RSTFLAG = 0x4;
static MASK PSHFLAG = 0x8;
static MASK ACKFLAG = 0x10;
static MASK URGFLAG = 0x20;

class PacketTCP
{
public:
	PacketTCP(void)
	{
		_packet = new unsigned char[len()];
		memset(_packet, 0, len());
		setPointers();	
	};
	virtual ~PacketTCP(void)
	{
		delete[] _packet;
	};
	size_t len(void)
	{
		return (2*PORTLEN+SEQLEN+ACKLEN+
			OFFSETLEN+RESERVEDLEN+FLAGLEN+
			WINDOWSIZELEN+CHECKSUMLEN+
			URGENTPOINTERLEN)>>3;
	};
	unsigned char* packet(void)
	{
		return _packet;
	};
	void srcPort(const std::string& src, const unsigned int radix)
	{
		Utilities::toBytes(src, _srcPort, PORTLEN>>3, radix);		
	};	
	void dstPort(const std::string& dst, const unsigned int radix)
	{
		Utilities::toBytes(dst, _dstPort, PORTLEN>>3, radix);		
	};
	void seq(const std::string& seq, const unsigned int radix)
	{
		Utilities::toBytes(seq, _seq, SEQLEN>>3, radix);		
	};
	void ack(const std::string& ack, const unsigned int radix)
	{
		Utilities::toBytes(ack, _ack, ACKLEN>>3, radix);		
	};
	void offset(const std::string& offset, const unsigned int radix)
	{
		unsigned char _offset = 0;		
		Utilities::toBytes(offset, &_offset, 0, radix, OFFSETLEN);	
		//network order		
		*_offsResFlags |= (_offset << 4) & OFFSET;		
	};
	void reserved(const std::string& reserved, const unsigned int radix)
	{
		unsigned char _reserved = 0;		
		Utilities::toBytes(reserved, &_reserved, 0, radix, RESERVEDLEN);	
		//network order
		*_offsResFlags |= (_reserved << 1) & RESERVED;		
	};
	void flags(const std::string& flags, const unsigned int radix)
	{
		unsigned char _flags = 0;		
		Utilities::toBytes(flags, &_flags, 0, radix, FLAGLEN);	
		//network order
		*(_offsResFlags+1) |= _flags & FLAGS;		
	};
	void finFlag(const bool fin)
	{
		fin ? *(_offsResFlags+1) |= FINFLAG : 
			*(_offsResFlags+1) &= ~FINFLAG;				
	};
	void synFlag(const bool syn)
	{
		syn ? *(_offsResFlags+1) |= SYNFLAG : 
			*(_offsResFlags+1) &= ~SYNFLAG;				
	};
	void rstFlag(const bool rst)
	{
		rst ? *(_offsResFlags+1) |= RSTFLAG : 
			*(_offsResFlags+1) &= ~RSTFLAG;				
	};
	void pshFlag(const bool psh)
	{
		psh ? *(_offsResFlags+1) |= PSHFLAG : 
			*(_offsResFlags+1) &= ~PSHFLAG;				
	};
	void ackFlag(const bool ack)
	{
		ack ? *(_offsResFlags+1) |= ACKFLAG : 
			*(_offsResFlags+1) &= ~ACKFLAG;				
	};
	void urgFlag(const bool urg)
	{
		urg ? *(_offsResFlags+1) |= URGFLAG : 
			*(_offsResFlags+1) &= ~URGFLAG;				
	};

	void windowSize(const std::string& ws, const unsigned int radix)
	{
		Utilities::toBytes(ws, _windowSize, WINDOWSIZELEN>>3, radix);		
	};
	void checksum(const std::string& checksum, const unsigned int radix)
	{
		Utilities::toBytes(checksum, _checksum, CHECKSUMLEN>>3, radix);		
	};
	void urgentPointer(const std::string& urgentPointer, const unsigned int radix)
	{
		Utilities::toBytes(urgentPointer, _urgentPointer, URGENTPOINTERLEN>>3, radix);		
	};
private:
	PacketTCP(const PacketTCP&);
	void setPointers(void)
	{
		_srcPort = _packet;
		_dstPort = _srcPort + (PORTLEN>>3);
		_seq = _dstPort + (PORTLEN>>3);
		_ack = _seq + (SEQLEN>>3);
		_offsResFlags = _ack + (ACKLEN>>3); 
		_windowSize = _offsResFlags + (OFFSRESFLAGSLEN>>3);;
		_checksum = _windowSize + (WINDOWSIZELEN>>3);
		_urgentPointer = _checksum + (CHECKSUMLEN>>3);
	};
	unsigned char* _packet;
	unsigned char* _srcPort;
	unsigned char* _dstPort;
	unsigned char* _seq;
	unsigned char* _ack;
	unsigned char* _offsResFlags;
	unsigned char* _windowSize;
	unsigned char* _checksum;
	unsigned char* _urgentPointer;
	//TODO: options and data
};
}

#endif
