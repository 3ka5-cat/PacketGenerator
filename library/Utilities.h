#ifndef _UTILS_H_

#define _UTILS_H_
#include "debug.h"
#include <string>
#include <sstream>
class Utilities
{
public:	
	static void toBytes(const std::string& src, unsigned char* dst, 
		const size_t len, const unsigned int radix, const size_t bitLen = 0);
	
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
};

#endif