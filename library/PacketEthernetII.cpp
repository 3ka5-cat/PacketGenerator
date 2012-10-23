#include "PacketEthernetII.h"

using namespace std;

PacketEthernetII::PacketEthernetII(const std::string& src, const std::string& dst,
	const std::string& type, const unsigned int radix) 
{
	setPointers();
	Utilities::toBytes(src, _macSrc, MACADDRLEN, radix);
	Utilities::toBytes(dst, _macDst, MACADDRLEN, radix);
	Utilities::toBytes(type, _ethType, MACTYPELEN, radix);	
};