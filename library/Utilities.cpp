#include "Utilities.h"

using namespace std;

TOKENS& Utilities::split(const TOKEN& s, char delim, TOKENS &elems) 
{
    stringstream ss(s);
    string item;
    while(getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}

TOKENS Utilities::split(const TOKEN &s, char delim)
{
    TOKENS elems;
    return split(s, delim, elems);
}

TokenAndRadix Utilities::getTokenAndRadix(TOKEN& formattedToken)
{
	TOKENS tokens = Utilities::split(formattedToken,TOKENDELIM);
	TOKEN token = tokens[0];
	stringstream stream(tokens[1]);				
	unsigned int radix = 0;
	stream >> radix;
	TokenAndRadix ret;
	ret.radix = radix;
	ret.token = token;
	return ret;
}

bool Utilities::parseUDPFormat(const string& formatStr, TokenAndRadix& src,
	TokenAndRadix& dst,	TokenAndRadix& checksum, TokenAndRadix& pktLen)
{
	//UDP:src,radix>dst,radix;checksum,radix;pktLen,radix;
	TOKENS parts = Utilities::split(formatStr,HEADERBODYDELIM);
	if (parts.size() == 2 && parts[0] == UDPID) {		
		TOKENS bodyTokens = Utilities::split(parts[1],BODYDELIM);
		if (bodyTokens.size() == 3) {
			TOKENS addressTokens = Utilities::split(bodyTokens[0],SRCDSTDELIM);
			if (addressTokens.size() == 2) {
				src = getTokenAndRadix(addressTokens[0]);
				dst = getTokenAndRadix(addressTokens[1]);
			}
			else 
				return false;			
			checksum = getTokenAndRadix(bodyTokens[1]);	
			pktLen = getTokenAndRadix(bodyTokens[2]);	
			return true;
		}
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
	TOKENS parts = Utilities::split(formatStr,HEADERBODYDELIM);
	if (parts.size() == 2 && parts[0] == ICMPID) {		
		TOKENS bodyTokens = Utilities::split(parts[1],BODYDELIM);
		if (bodyTokens.size() == 5) {
			type  =  getTokenAndRadix(bodyTokens[0]);	
			code = getTokenAndRadix(bodyTokens[1]);	
			checksum = getTokenAndRadix(bodyTokens[2]);	
			id = getTokenAndRadix(bodyTokens[3]);	
			seq = getTokenAndRadix(bodyTokens[4]);	
			return true;
		}
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
	//TCP:src,radix>dst,radix;seq,radix;ack,radix;offset,radix;reserved,radix;
	//flags,radix;windowSize,radix;checksum,radix;urgentPointer,radix;
	TOKENS parts = Utilities::split(formatStr,HEADERBODYDELIM);
	if (parts.size() == 2 && parts[0] == TCPID) {		
		TOKENS bodyTokens = Utilities::split(parts[1],BODYDELIM);
		if (bodyTokens.size() == 9) {			
			TOKENS addressTokens = Utilities::split(bodyTokens[0],SRCDSTDELIM);
			if (addressTokens.size() == 2) {
				src = getTokenAndRadix(addressTokens[0]);
				dst = getTokenAndRadix(addressTokens[1]);
			}
			else 
				return false;			
			seq = getTokenAndRadix(bodyTokens[1]);	
			ack = getTokenAndRadix(bodyTokens[2]);	
			offset = getTokenAndRadix(bodyTokens[3]);	
			reserved = getTokenAndRadix(bodyTokens[4]);	
			flags = getTokenAndRadix(bodyTokens[5]);	
			windowSize = getTokenAndRadix(bodyTokens[6]);	
			checksum = getTokenAndRadix(bodyTokens[7]);	
			urgentPointer = getTokenAndRadix(bodyTokens[8]);
			return true;
		}
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
	TOKENS parts = Utilities::split(formatStr,HEADERBODYDELIM);
	if (parts.size() == 2 && parts[0] == IPV4ID) {		
		TOKENS bodyTokens = Utilities::split(parts[1],BODYDELIM);
		if (bodyTokens.size() == 12) {						
			version = getTokenAndRadix(bodyTokens[0]);	
			ihl = getTokenAndRadix(bodyTokens[1]);
			tos = getTokenAndRadix(bodyTokens[2]);	
			pktLen = getTokenAndRadix(bodyTokens[3]);	
			id = getTokenAndRadix(bodyTokens[4]);	
			flags = getTokenAndRadix(bodyTokens[5]);	
			offset = getTokenAndRadix(bodyTokens[6]);	
			ttl = getTokenAndRadix(bodyTokens[7]);	
			protocol = getTokenAndRadix(bodyTokens[8]);
			hdrChecksum = getTokenAndRadix(bodyTokens[9]);
			src = getTokenAndRadix(bodyTokens[10]);		
			dst = getTokenAndRadix(bodyTokens[11]);	
			return true;
		}
		else
			return false;		
	}
	else
		return false;	
}

bool Utilities::parseEthFormat(const string& formatStr, TokenAndRadix& src, 
	TokenAndRadix& dst, TokenAndRadix& type)
{
	//ETH2:src,radix>dst,radix;type,radix;
	TOKENS parts = Utilities::split(formatStr,HEADERBODYDELIM);
	if (parts.size() == 2 && parts[0] == ETH2ID) {		
		TOKENS bodyTokens = Utilities::split(parts[1],BODYDELIM);
		if (bodyTokens.size() == 2) {
			TOKENS addressTokens = Utilities::split(bodyTokens[0],SRCDSTDELIM);
			if (addressTokens.size() == 2) {
				src = getTokenAndRadix(addressTokens[0]);
				dst = getTokenAndRadix(addressTokens[1]);
			}
			else 
				return false;			
			type = getTokenAndRadix(bodyTokens[1]);	
			return true;
		}
		else
			return false;		
	}
	else
		return false;	
}


void Utilities::toBytes(const std::string& src, unsigned char* dst, 
		const size_t len, const unsigned int radix, const size_t bitLen)
{
	//TODO: correct len in bytes 1,2,4?  Add check for incorrect 3 byte length
	//or discover how to convert to network byte order 3 byte length field

	// if size of destination is less than byte, then len argument must be 0,
	// and bitLen argument must be set to size of destination in bits
	// one of these two arguments must be 0, anyway
	if ((!len && bitLen && bitLen <= 32) || (!bitLen && len)) {
		if (radix == 16 && bitLen)
			Utilities::hex2bits(src, dst, bitLen);
		else if (radix == 16)
			Utilities::hex2bytes(src, dst, len);
		else if (radix == 10 && len && len <= 4)
			Utilities::dec2bytes(src, dst, len);
		else if (radix == 10 && bitLen)
			Utilities::dec2bits(src, dst, bitLen);
		else if (radix == 10) {
			DbgMsg(__FILE__, __LINE__,
				"Utilities::toBytes() ERROR: Invalid radix 10: maxmimum four-octet fields\
				can be filled by decimal string\n");
			throw std::invalid_argument("Invalid radix. Maxmimum "
										"four-octet fields "
										"can be filled by decimal string");			
		}
		else {		
			DbgMsg(__FILE__, __LINE__,
				"Utilities::toBytes() ERROR: Invalid radix == %u\n", radix);
			throw std::invalid_argument("Invalid radix");
		}
	}		
	else {		
		DbgMsg(__FILE__, __LINE__,
				"Utilities::toBytes() ERROR: Invalid length arguments: len in bytes == %u,\
				len in bits == %u. One of these two arguments must be 0\
				and len in bits can't be more than 32\n", len, bitLen);
		throw std::invalid_argument("Invalid length arguments, one of them must be 0\
									and length in bits can't be more than 32");
	}
}

void Utilities::hex2bytes(const std::string& src, unsigned char* dst, 
	const size_t len)
{		
	if (src.size() != 2*len)
		throw std::invalid_argument("Invalid hexadecimal string length at " + src);
	if (!checkForbiddenHex(src))
		throw std::invalid_argument("Non-hexadecimal symbol at " + src);			
	const char *pos = src.c_str();
	size_t count = 0;
	unsigned int tmp = 0;		
	for(unsigned int i = 0, count = 0; count < len; count++) {
		sscanf(pos, "%2hhx", &tmp);	
		dst[count] = tmp >> 0;
		pos += 2 * sizeof(char);
	}
};

void Utilities::dec2bytes(const std::string& src, unsigned char* dst,
	const size_t len)
{	
	if (!checkForbiddenDec(src))
		throw std::invalid_argument("Non-decimal symbol at " + src);
	unsigned long value = strtoul(src.c_str(), NULL, 10);
	if (value == ULONG_MAX && errno == ERANGE) {
		DbgMsg(__FILE__, __LINE__, 
			"Utilities::dec2bytes() ERROR: Invalid decimal string \"%s\".\n");		
		throw std::invalid_argument("Invalid decimal string " + src);
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

void Utilities::hex2bits(const std::string& src, unsigned char* dst, 
		const size_t bitLen)
{
	throw std::invalid_argument("Invalid radix: hex2 bits is temporary\
								not implemented\n");
}


void Utilities::dec2bits(const std::string& src, unsigned char* dst, 
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
		throw std::invalid_argument("Non-decimal symbol at string \"" + src + "\"");
	unsigned long value = strtoul(src.c_str(), NULL, 10);	
	if (value > value_MAX) {
		DbgMsg(__FILE__, __LINE__, 
			"Utilities::dec2bits() ERROR: Invalid decimal string \"%s\".\n\
			Bit length == %u, Maximum value == %u\n", src.c_str(), bitLen, value_MAX);			
		throw std::invalid_argument("Invalid decimal string \"" + src + "\"");
	}
	size_t add = 0;
	if ((bitLen % 8) != 0)
		add = 8 - (bitLen - 8 * (bitLen / 8));
	memcpy(dst,&value, (bitLen + add)/8);
}

bool Utilities::checkForbiddenHex(const std::string& in)
{
	if (in.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
		return false;
	return true;						
};

bool Utilities::checkForbiddenDec(const std::string& in)
{
	if (in.find_first_not_of("0123456789") != std::string::npos)
		return false;
	return true;						
};