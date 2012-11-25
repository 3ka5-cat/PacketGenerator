#ifndef _UTILS_H_

#define _UTILS_H_
#include "debug.h"
#include <string>
#include <sstream>
#include <vector>
typedef std::vector<std::string> Tokens;
typedef std::string Token;

static const Token ICMPPROTO = "ICMP";
static const Token TCPPROTO = "TCP";
static const Token UDPPROTO = "UDP";
static const Token IPV4PROTO = "IPv4";
static const Token ETH2PROTO = "ETH2";

typedef struct _TokenAndRadix {
		Token token;
		unsigned int radix;
} TokenAndRadix;

typedef const unsigned char FORMATDELIMITER;
static FORMATDELIMITER HEADERBODYDELIM=':';
static FORMATDELIMITER BODYDELIM=';';
static FORMATDELIMITER TOKENDELIM=',';

class Utilities
{
public:	
	static bool startsWith(const std::string& text,const std::string& token);	
	static void toBytes(const std::string& src, unsigned char* dst, 
		const size_t len, const unsigned int radix, const size_t bitLen = 0);
	static bool parseIPv4Format(const std::string& formatStr, TokenAndRadix& version, 
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
	static bool createEthFormat(const Token& src, const Token& dst, const Token& type,
		Token& result);
	static Token createIPv4Format(const Token& version, 
		const Token& ihl, const Token& tos, const Token& pktLen, 
		const Token& id, const Token& flags, const Token& offset, 
		const Token& ttl, const Token& protocol, const Token& hdrChecksum, 
		const Token& src, const Token& dst);
	static Token createUDPFormat(const Token& src, const Token& dst,
		const Token& checksum, const Token& pktLen);
	static Token createTCPFormat(const Token& src, 
		const Token& dst, const Token& seq, const Token& ack, 
		const Token& offset, const Token& reserved, const Token& flags, 
		const Token& windowSize, const Token& checksum, 
		const Token& urgentPointer);
	
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

	static Tokens& split(const Token& s, 
		char delim, Tokens& elems);
	static Tokens split(const Token &s, char delim);
	static bool getTokenAndRadix(TokenAndRadix& result, Token& formattedToken);
	static bool addToken(Token& result, const Token& token);
};
#endif