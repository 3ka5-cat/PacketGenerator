#ifndef _PKT_GEN_H_

#define _PKT_GEN_H_
#include "common.h"
#include <vector>
#include "Device.h"
#include "FileWorker.h"

//#define UNMANAGEDDLL_API __declspec(dllexport)

typedef std::vector<Device*> Devices;

class PktGen
{
public:
	PktGen(void);
	virtual ~PktGen(void);
	unsigned int totalDevices(void)
	{
		return _devices.size();
	};
	Devices& devices(void)
	{
		return _devices;
	};	
	Device* device(unsigned int device);		
private:
	PktGen(const PktGen&);
	void fillDevices(void);
	Devices _devices;
	pcap_if_t* _alldevs;	
};

#endif