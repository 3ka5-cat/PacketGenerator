#include "PacketEthernetII.h"

using namespace std;
using namespace ETH2;

PacketEthernetII::PacketEthernetII(const std::string& src, const std::string& dst,
	const std::string& type, const unsigned int radix) 
{
	setPointers();
	this->dst(dst, radix);
	this->src(src, radix);
	this->type(type, radix);	
};