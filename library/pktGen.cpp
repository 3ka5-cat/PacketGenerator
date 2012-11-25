#include "pktGen.h"

PktGen::PktGen(void) : _alldevs(NULL)
{
	//temporarily
	DbgInit("test.log");
	fillDevices();	
}

PktGen::~PktGen(void)
{
	if (_alldevs)
		pcap_freealldevs(_alldevs);
}

Device* PktGen::device(unsigned int device)
{
	if (_alldevs && device >= 0 && device < totalDevices())
		return _devices[device];
	else {
		setGlobalError("No such device"); 
		if (!_alldevs)
			DbgMsg(__FILE__, __LINE__, 
			"PktGen::device ERROR: trying to select device\
			from uninitialized _alldevs\n");
		else
			DbgMsg(__FILE__, __LINE__, 
			"PktGen::device ERROR: trying to select device\
			with wrong number %u\n", device);
		return NULL;
	}
};	

/* Retrieve the device list from the local machine */
void PktGen::fillDevices(void)
{
	char errbuf[PCAP_ERRBUF_SIZE];			
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &_alldevs,
			errbuf) == -1) {
		setGlobalError("Error while getting network interfaces"); 
		DbgMsg(__FILE__, __LINE__, 
			"PktGen::fillDevices() pcap_findalldevs_ex() ERROR: %s\n", errbuf);				
		return;
	}

	/* Fill the list */
	int i = 0;
	for (pcap_if_t* dev = _alldevs; dev != NULL; dev = dev->next, i++) {
		Device* device = new Device(dev);
		_devices.push_back(device);
	}

	if (i == 0) {
		setGlobalError("No interfaces found! Make sure WinPcap is installed"); 
		DbgMsg(__FILE__, __LINE__, 
			"PktGen::fillDevices() ERROR: allDevices list, received from\
			pcap_findalldevs_ex() is empty\n");
		pcap_freealldevs(_alldevs);
		return;
	}
}