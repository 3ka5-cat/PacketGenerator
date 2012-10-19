#ifndef _UTILS_H_

#define _UTILS_H_

class Utilities
{
public:	
	static void hex2bytes(const char* src, unsigned char* dst, 
		const unsigned int len)
	{
		// check hex string for correct length
		if (strlen(src) != 2*len)
			throw std::range_error("Incorrect hex string length");
		const char *pos = src;
		size_t count = 0;
		/* WARNING: no sanitization or error-checking whatsoever */
		unsigned int tmp = 0;		
		for(unsigned int i = 0, count = 0; count < len; count++) {
			sscanf(pos, "%2hhx", &tmp);	
			dst[count] = tmp >> 0;
			pos += 2 * sizeof(char);
		}		
	};	
};

#endif