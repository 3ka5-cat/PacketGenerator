#ifndef _PKT_GEN_H_

#define _PKT_GEN_H_
#include "common.h"
#include <vector>
#include "Device.h"

typedef std::vector<Device*> Devices;

class PktGen
{
public:
	PktGen(void);
	virtual ~PktGen(void);
	pcap_if_t* allDevices(void)
	{
		return _alldevs;
	};
	unsigned int totalDevices(void)
	{
		return _devices.size();
	};
	Devices& devices(void)
	{
		return _devices;
	};
	void sendPacket(int device);
private:
	PktGen(const PktGen&);
	void fillDevices(void);
	Devices _devices;
	pcap_if_t* _alldevs;
};

#endif