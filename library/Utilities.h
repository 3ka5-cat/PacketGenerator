#ifndef _UTILS_H_

#define _UTILS_H_
#include <string>
class Utilities
{
public:	
	static void toBytes(const std::string& src, unsigned char* dst, 
		const size_t len, const unsigned int radix)
	{
		if (radix == 16)
			Utilities::hex2bytes(src, dst, len);	
		else if (radix == 10) {
			if (len <= 4 )
				Utilities::dec2bytes(src, dst);	
			else
				throw std::invalid_argument("Invalid radix. Maxmimum "
											"four-octet fields "
											"can be filled by decimal string");
		}
		else		
			throw std::invalid_argument("Invalid radix");
	}
	static void hex2bytes(const std::string& src, unsigned char* dst, 
		const size_t len);
	static void dec2bytes(const std::string& src, unsigned char* dst);
	static bool checkForbiddenHex(const std::string& in);
	static bool checkForbiddenDec(const std::string& in);
};

#endif