#ifndef _UTILS_H_

#define _UTILS_H_
#include "debug.h"
#include <string>
#include <sstream>
#include <vector>
typedef std::vector<std::string> TOKENS;
typedef std::string TOKEN;
typedef struct _TokenAndRadix {
		TOKEN token;
		unsigned int radix;
} TokenAndRadix;
typedef const std::string PROTOCOLFORMATID;
typedef const unsigned char FORMATDELIMITER;
static PROTOCOLFORMATID ICMPID="ICMP";
static PROTOCOLFORMATID UDPID="UDP";
static PROTOCOLFORMATID TCPID="TCP";
static PROTOCOLFORMATID ETH2ID="ETH2";
static PROTOCOLFORMATID IPV4ID="IPv4";
static FORMATDELIMITER HEADERBODYDELIM=':';
static FORMATDELIMITER BODYDELIM=';';
static FORMATDELIMITER SRCDSTDELIM='>';
static FORMATDELIMITER TOKENDELIM=',';

class Utilities
{
public:	
	static void toBytes(const std::string& src, unsigned char* dst, 
		const size_t len, const unsigned int radix, const size_t bitLen = 0);
	static bool Utilities::parseIPv4Format(const std::string& formatStr, TokenAndRadix& version, 
		TokenAndRadix& ihl, TokenAndRadix& tos, TokenAndRadix& pktLen, 
		TokenAndRadix& id, TokenAndRadix& flags, TokenAndRadix& offset, 
		TokenAndRadix& ttl, TokenAndRadix& protocol, TokenAndRadix& hdrChecksum, 
		TokenAndRadix& src, TokenAndRadix& dst);
	static bool parseICMPFormat(const std::string& formatStr, TokenAndRadix& type,
		TokenAndRadix& code, TokenAndRadix& checksum, TokenAndRadix& id, TokenAndRadix& seq);
	static bool parseUDPFormat(const std::string& formatStr, TokenAndRadix& src,
	TokenAndRadix& dst,	TokenAndRadix& checksum, TokenAndRadix& pktLen);
	static bool parseTCPFormat(const std::string& formatStr, TokenAndRadix& src, 
		TokenAndRadix& dst, TokenAndRadix& seq, TokenAndRadix& ack, 
		TokenAndRadix& offset, TokenAndRadix& reserved, TokenAndRadix& flags, 
		TokenAndRadix& windowSize, TokenAndRadix& checksum, 
		TokenAndRadix& urgentPointer);
	static bool parseEthFormat(const std::string& formatStr, TokenAndRadix& src, 
		TokenAndRadix& dst, TokenAndRadix& type);
	
private:	
	static void hex2bytes(const std::string& src, unsigned char* dst, 
		const size_t len);
	static void dec2bytes(const std::string& src, unsigned char* dst,
		const size_t len);
	static void hex2bits(const std::string& src, unsigned char* dst, 
		const size_t bitLen);
	static void dec2bits(const std::string& src, unsigned char* dst, 
		const size_t bitLen);
	
	static bool checkForbiddenHex(const std::string& in);
	static bool checkForbiddenDec(const std::string& in);

	static TOKENS& split(const TOKEN& s, 
		char delim, TOKENS& elems);
	static TOKENS split(const TOKEN &s, char delim);
	static TokenAndRadix getTokenAndRadix(TOKEN& formattedToken);
};
#endif