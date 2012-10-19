#include "PacketEthernetII.h"

using namespace std;

PacketEthernetII::PacketEthernetII(const char* src, const char* dst,
	const char* type) 
{		
	if(strlen(src) != 2*MACADDRLEN)
		throw range_error("Incorrect source MAC address length");
	if(strlen(dst) != 2*MACADDRLEN)
		throw range_error("Incorrect destination MAC address length");
	if(strlen(type) != 2*MACTYPELEN)
		throw range_error("Incorrect Ethernet type length");
	_macDst = _packet;
	_macSrc = _packet + MACADDRLEN;
	_ethType = _packet + 2 * MACADDRLEN;

	Utilities::hex2bytes(src,_macSrc,MACADDRLEN);
	Utilities::hex2bytes(dst,_macDst,MACADDRLEN);	
	Utilities::hex2bytes(type,_ethType,MACTYPELEN);	
};