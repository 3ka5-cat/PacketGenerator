#ifndef _PKT_GEN_H_

#define _PKT_GEN_H_
#include "common.h"
#include <vector>
#include "Device.h"


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
	Device& device(unsigned int device)
	{
		if (_alldevs && device > 0 && device < totalDevices())
			return *_devices[device];
		else {
			std::cerr << "No such device" << std::endl; 
			if (!_alldevs)
				DbgMsg(__FILE__, __LINE__, 
					"PktGen::device ERROR: trying to select device\
					from uninitialized _alldevs\n");
			else
				DbgMsg(__FILE__, __LINE__, 
					"PktGen::device ERROR: trying to select device\
					with wrong number %u\n", device);
		}
	};	
private:
	PktGen(const PktGen&);
	void fillDevices(void);
	Devices _devices;
	pcap_if_t* _alldevs;
};

#endif