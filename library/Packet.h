#ifndef _PKT_H_

#define _PKT_H_
#include <string>
class Packet
{
public:
	Packet(void) 
	{		
		_packet = new unsigned char[len()];
		memset(_packet, 0, len());
		setPointers();			
	};
	virtual ~Packet(void)
	{
		delete[] _packet;
	}
	virtual size_t len(void) = 0;	
	unsigned char* packet(void)
	{
		return _packet;
	};
private:
	Packet(const Packet&);
	virtual void setPointers(void) = 0;
	unsigned char* _packet;
};

#endif