#include "Utilities.h"

using namespace std;

Tokens& Utilities::split(const Token& s, char delim, Tokens &elems) 
{
    stringstream ss(s);
    string item;
    while(getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}

Tokens Utilities::split(const Token &s, char delim)
{
    Tokens elems;
    return split(s, delim, elems);
}

bool Utilities::startsWith(const string& text, const string& token)
{
	if(text.length() < token.length())
		return false;
	return (text.compare(0, token.length(), token) == 0);
}

bool Utilities::createEthFormat(const Token& src, 
	const Token& dst, const Token& type, Token& result)
{
	//"ETH2:111111111111,16;DCA97150BDBA,16;0800,16;"
	Tokens list = split(src, TOKENDELIM);	
	result = ETH2PROTO;
	result += HEADERBODYDELIM;
	if (addToken(result,src) && addToken(result,dst)
		&& addToken(result,type))
		return true;
	else
		return false;
}

Token Utilities::createIPv4Format(const Token& version, 
	const Token& ihl, const Token& tos, const Token& pktLen, 
	const Token& id, const Token& flags, const Token& offset, 
	const Token& ttl, const Token& protocol, const Token& hdrChecksum, 
	const Token& src, const Token& dst)
{
	//IPv4:version,radix;ihl,radix;tos,radix;pktLen,radix;id,radix;flags,radix;
	//offset,radix;ttl,radix;protocol,radix;hdrChecksum,radix;src,radix;dst,radix;
	Token result = IPV4PROTO;
	result += HEADERBODYDELIM;
	addToken(result,version);
	addToken(result,ihl);
	addToken(result,tos);
	addToken(result,pktLen);
	addToken(result,id);
	addToken(result,flags);
	addToken(result,offset);
	addToken(result,ttl);
	addToken(result,protocol);
	addToken(result,hdrChecksum);
	addToken(result,src);
	addToken(result,dst);
	return result;
}

Token Utilities::createUDPFormat(const Token& src, const Token& dst,
	const Token& checksum, const Token& pktLen)
{
	//UDP:src,radix;dst,radix;checksum,radix;pktLen,radix;
	Token result = UDPPROTO;
	result += HEADERBODYDELIM;
	addToken(result,src);
	addToken(result,dst);
	addToken(result,checksum);
	addToken(result,pktLen);
	return result;
}

Token Utilities::createTCPFormat(const Token& src, 
	const Token& dst, const Token& seq, const Token& ack, 
	const Token& offset, const Token& reserved, const Token& flags, 
	const Token& windowSize, const Token& checksum, 
	const Token& urgentPointer)
{
	//TCP:src,radix;dst,radix;seq,radix;ack,radix;offset,radix;reserved,radix;
	//flags,radix;windowSize,radix;checksum,radix;urgentPointer,radix;
	Token result = TCPPROTO;
	result += HEADERBODYDELIM;
	addToken(result,src);
	addToken(result,dst);
	addToken(result,seq);
	addToken(result,ack);	
	addToken(result,offset);
	addToken(result,reserved);
	addToken(result,flags);
	addToken(result,windowSize);
	addToken(result,checksum);
	addToken(result,urgentPointer);
	return result;
}

bool Utilities::addToken(Token& result, const Token& token)
{
	Tokens list = split(token, TOKENDELIM);	
	if (list.size() == 2) {
		result += list[0];
		result += TOKENDELIM;
		result += list[1];
		result += BODYDELIM;
		return true;
	}	
	else 
		return false;
}

 bool Utilities::getTokenAndRadix(TokenAndRadix& result, Token& formattedToken)
{
	Tokens tokens = Utilities::split(formattedToken,TOKENDELIM);
	if (tokens.size() == 2) {
		Token token = tokens[0];
		stringstream stream(tokens[1]);				
		unsigned int radix = 0;
		stream >> radix;
		result.radix = radix;
		result.token = token;
		return true;
	}
	else
		return false;	
}

bool Utilities::parseUDPFormat(const string& formatStr, TokenAndRadix& src,
	TokenAndRadix& dst,	TokenAndRadix& checksum, TokenAndRadix& pktLen)
{
	//UDP:src,radix;dst,radix;checksum,radix;pktLen,radix;
	Tokens parts = Utilities::split(formatStr,HEADERBODYDELIM);
	if (parts.size() == 2 && parts[0] == UDPPROTO) {		
		Tokens bodyTokens = Utilities::split(parts[1],BODYDELIM);
		if (bodyTokens.size() == 4 && 
			getTokenAndRadix(src,bodyTokens[0]) && 
			getTokenAndRadix(dst,bodyTokens[1]) &&
			getTokenAndRadix(checksum,bodyTokens[2]) &&
			getTokenAndRadix(pktLen,bodyTokens[3]))
			return true;
		else				
			return false;			
		}
	else
		return false;	
}

bool Utilities::parseICMPFormat(const string& formatStr, TokenAndRadix& type,
	TokenAndRadix& code, TokenAndRadix& checksum, TokenAndRadix& id, TokenAndRadix& seq)
{
	//ICMP:type,radix;code,radix;checksum,radix;id,radix;seq,radix;
	Tokens parts = Utilities::split(formatStr,HEADERBODYDELIM);
	if (parts.size() == 2 && parts[0] == ICMPPROTO) {		
		Tokens bodyTokens = Utilities::split(parts[1],BODYDELIM);
		if (bodyTokens.size() == 5 && 
			getTokenAndRadix(type, bodyTokens[0]) &&
			getTokenAndRadix(code, bodyTokens[1]) &&
			getTokenAndRadix(checksum, bodyTokens[2]) &&
			getTokenAndRadix(id, bodyTokens[3]) &&
			getTokenAndRadix(seq, bodyTokens[4]))
			return true;
		else
			return false;
	}
	else
		return false;
}

bool Utilities::parseTCPFormat(const string& formatStr, TokenAndRadix& src, 
	TokenAndRadix& dst, TokenAndRadix& seq, TokenAndRadix& ack, 
	TokenAndRadix& offset, TokenAndRadix& reserved, TokenAndRadix& flags, 
	TokenAndRadix& windowSize, TokenAndRadix& checksum, 
	TokenAndRadix& urgentPointer)
{
	//TCP:src,radix;dst,radix;seq,radix;ack,radix;offset,radix;reserved,radix;
	//flags,radix;windowSize,radix;checksum,radix;urgentPointer,radix;
	Tokens parts = Utilities::split(formatStr,HEADERBODYDELIM);
	if (parts.size() == 2 && parts[0] == TCPPROTO) {		
		Tokens bodyTokens = Utilities::split(parts[1],BODYDELIM);
		if (bodyTokens.size() == 10 &&
			getTokenAndRadix(src, bodyTokens[0]) &&
			getTokenAndRadix(dst, bodyTokens[1]) &&
			getTokenAndRadix(seq, bodyTokens[2]) &&
			getTokenAndRadix(ack, bodyTokens[3]) &&
			getTokenAndRadix(offset, bodyTokens[4]) &&
			getTokenAndRadix(reserved, bodyTokens[5]) &&
			getTokenAndRadix(flags, bodyTokens[6]) &&
			getTokenAndRadix(windowSize, bodyTokens[7]) &&
			getTokenAndRadix(checksum, bodyTokens[8]) &&
			getTokenAndRadix(urgentPointer, bodyTokens[9]))
			return true;
		else
			return false;
	}
	else 
		return false;
}

bool Utilities::parseIPv4Format(const string& formatStr, TokenAndRadix& version, 
	TokenAndRadix& ihl, TokenAndRadix& tos, TokenAndRadix& pktLen, 
	TokenAndRadix& id, TokenAndRadix& flags, TokenAndRadix& offset, 
	TokenAndRadix& ttl, TokenAndRadix& protocol, TokenAndRadix& hdrChecksum, 
	TokenAndRadix& src, TokenAndRadix& dst)
{
	//IPv4:version,radix;ihl,radix;tos,radix;pktLen,radix;id,radix;flags,radix;
	//offset,radix;ttl,radix;protocol,radix;hdrChecksum,radix;src,radix;dst,radix;
	Tokens parts = Utilities::split(formatStr,HEADERBODYDELIM);
	if (parts.size() == 2 && parts[0] == IPV4PROTO) {		
		Tokens bodyTokens = Utilities::split(parts[1],BODYDELIM);
		if (bodyTokens.size() == 12 &&					
			getTokenAndRadix(version, bodyTokens[0])&&	
			getTokenAndRadix(ihl, bodyTokens[1])&&
			getTokenAndRadix(tos, bodyTokens[2])&&	
			getTokenAndRadix(pktLen, bodyTokens[3])&&	
			getTokenAndRadix(id, bodyTokens[4])&&	
			getTokenAndRadix(flags, bodyTokens[5])&&	
			getTokenAndRadix(offset, bodyTokens[6])&&	
			getTokenAndRadix(ttl, bodyTokens[7])&&	
			getTokenAndRadix(protocol, bodyTokens[8])&&
			getTokenAndRadix(hdrChecksum, bodyTokens[9])&&
			getTokenAndRadix(src, bodyTokens[10])&&
			getTokenAndRadix(dst, bodyTokens[11]))
			return true;
		else
			return false;
		}
	else
		return false;	
}

bool Utilities::parseEthFormat(const string& formatStr, TokenAndRadix& src, 
	TokenAndRadix& dst, TokenAndRadix& type)
{
	//ETH2:src,radix;dst,radix;type,radix;
	Tokens parts = Utilities::split(formatStr,HEADERBODYDELIM);
	if (parts.size() == 2 && parts[0] == ETH2PROTO) {		
		Tokens bodyTokens = Utilities::split(parts[1],BODYDELIM);
		if (bodyTokens.size() == 3 && 
			getTokenAndRadix(src, bodyTokens[0]) &&
			getTokenAndRadix(dst, bodyTokens[1]) &&
			getTokenAndRadix(type, bodyTokens[2]))
			return true;
		else
			return false;
	}
	else
		return false;
}


void Utilities::toBytes(const string& src, unsigned char* dst, 
		const size_t len, const unsigned int radix, const size_t bitLen)
{
	//TODO: correct len in bytes 1,2,4?  Add check for incorrect 3 byte length
	//or discover how to convert to network byte order 3 byte length field

	// if size of destination is less than byte, then len argument must be 0,
	// and bitLen argument must be set to size of destination in bits
	// one of these two arguments must be 0, anyway
	if ((!len && bitLen && bitLen <= 32) || (!bitLen && len)) {
		if (radix == 16 && bitLen)
			hex2bits(src, dst, bitLen);
		else if (radix == 16)
			hex2bytes(src, dst, len);
		else if (radix == 10 && len && len <= 4)
			dec2bytes(src, dst, len);
		else if (radix == 10 && bitLen)
			dec2bits(src, dst, bitLen);
		else if (radix == 10) {
			DbgMsg(__FILE__, __LINE__,
				"Utilities::toBytes() ERROR: Invalid radix 10: maxmimum four-octet fields\
				can be filled by decimal string\n");
			throw invalid_argument("Invalid radix. Maxmimum "
										"four-octet fields "
										"can be filled by decimal string");			
		}
		else {		
			DbgMsg(__FILE__, __LINE__,
				"Utilities::toBytes() ERROR: Invalid radix == %u\n", radix);
			throw invalid_argument("Invalid radix");
		}
	}		
	else {		
		DbgMsg(__FILE__, __LINE__,
				"Utilities::toBytes() ERROR: Invalid length arguments: len in bytes == %u,\
				len in bits == %u. One of these two arguments must be 0\
				and len in bits can't be more than 32\n", len, bitLen);
		throw invalid_argument("Invalid length arguments, one of them must be 0\
									and length in bits can't be more than 32");
	}
}

void Utilities::hex2bytes(const string& src, unsigned char* dst, 
	const size_t len)
{		
	if (src.size() != 2*len)
		throw invalid_argument("Invalid hexadecimal string length at " + src);
	if (!checkForbiddenHex(src))
		throw invalid_argument("Non-hexadecimal symbol at " + src);			
	const char *pos = src.c_str();
	size_t count = 0;
	unsigned int tmp = 0;		
	for(unsigned int i = 0, count = 0; count < len; count++) {
		sscanf(pos, "%2hhx", &tmp);	
		dst[count] = tmp >> 0;
		pos += 2 * sizeof(char);
	}
};

void Utilities::dec2bytes(const string& src, unsigned char* dst,
	const size_t len)
{	
	if (!checkForbiddenDec(src))
		throw invalid_argument("Non-decimal symbol at " + src);
	unsigned long value = strtoul(src.c_str(), NULL, 10);
	if (value == ULONG_MAX && errno == ERANGE) {
		DbgMsg(__FILE__, __LINE__, 
			"Utilities::dec2bytes() ERROR: Invalid decimal string \"%s\".\n");		
		throw invalid_argument("Invalid decimal string " + src);
	}
	
	// length argument is checked at toBytes(), and can't be less than 0
	// and more than 4, so it can be safely used in memcpy
	
	if (len == 4) {
		value = htonl(value);
		memcpy(dst,&value,len);
	}
	else if (len == 2) {
		unsigned short svalue = value;
		svalue = htons(svalue);
		memcpy(dst,&svalue,len);		
	}
	else 
		memcpy(dst,&value,len);
};

void Utilities::hex2bits(const string& src, unsigned char* dst, 
		const size_t bitLen)
{
	throw invalid_argument("Invalid radix: hex2 bits is temporary\
								not implemented\n");
}


void Utilities::dec2bits(const string& src, unsigned char* dst, 
		const size_t bitLen)
{
	// maximum length of input decimal number is 
	// 2 ^ (size of field in bits) - 1
	// log10 + 1 give length of this max number
	// 2 ^ (size of field in bits) == 1 << (size of field in bits)
	/*
	size_t maxStrSize = static_cast<size_t>(1 + log10(static_cast<double>((1 << bitLen) - 1)));
	if (src.size() > maxStrSize)
		throw std::invalid_argument("Incorrect decimal string length at " + src);
		*/
	const unsigned long value_MAX = (1 << bitLen) - 1;	
	if (!checkForbiddenDec(src))
		throw invalid_argument("Non-decimal symbol at string \"" + src + "\"");
	unsigned long value = strtoul(src.c_str(), NULL, 10);	
	if (value > value_MAX) {
		DbgMsg(__FILE__, __LINE__, 
			"Utilities::dec2bits() ERROR: Invalid decimal string \"%s\".\n\
			Bit length == %u, Maximum value == %u\n", src.c_str(), bitLen, value_MAX);			
		throw invalid_argument("Invalid decimal string \"" + src + "\"");
	}
	size_t add = 0;
	if ((bitLen % 8) != 0)
		add = 8 - (bitLen - 8 * (bitLen / 8));
	memcpy(dst,&value, (bitLen + add)/8);
}

bool Utilities::checkForbiddenHex(const string& in)
{
	if (in.find_first_not_of("0123456789abcdefABCDEF") != string::npos)
		return false;
	return true;						
};

bool Utilities::checkForbiddenDec(const string& in)
{
	if (in.find_first_not_of("0123456789") != string::npos)
		return false;
	return true;						
};