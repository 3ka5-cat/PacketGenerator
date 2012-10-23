#include "Utilities.h"

void Utilities::hex2bytes(const std::string& src, unsigned char* dst, 
	const size_t len)
{		
	if (src.size() != 2*len)
		throw std::invalid_argument("Incorrect hexadecimal string length at " + src);
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

void Utilities::dec2bytes(const std::string& src, unsigned char* dst)
{	// maximum length of input decimal number is 
	// 2 ^ (size of field in bytes) - 1
	// log10 + 1 give length of this max number
	// 2 ^ (size of field in bytes) == 1 << (size of field in bytes)
	//size_t maxStrSize = static_cast<size_t>(1 + log10(static_cast<double>((1 << (8*len)) - 1)));
	//if (src.size() > maxStrSize)
	//	throw std::invalid_argument("Incorrect decimal string length at " + src);
	if (!checkForbiddenDec(src))
		throw std::invalid_argument("Non-decimal symbol at " + src);
	unsigned long value = strtoul(src.c_str(), NULL, 10);
	if (value == ULONG_MAX && errno == ERANGE)
		throw std::invalid_argument("Incorrect decimal string " + src);
	memcpy(dst,&value,sizeof(value));		
};

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