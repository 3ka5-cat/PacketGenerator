#include "pktGen.h"

PktGen::PktGen(void) : _alldevs(NULL)
{
	fillDevices();	
}

PktGen::~PktGen(void)
{
	if (_alldevs)
		pcap_freealldevs(_alldevs);
}

/* Retrieve the device list from the local machine */
void PktGen::fillDevices(void)
{
	char errbuf[PCAP_ERRBUF_SIZE];			
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &_alldevs,
			errbuf) == -1) {
		std::cerr << "Error while getting network\
					 interfaces" << std::endl; 
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
		std::cerr << "No interfaces found! Make sure\
					 WinPcap is installed." << std::endl; 
		DbgMsg(__FILE__, __LINE__, 
			"PktGen::fillDevices() ERROR: allDevices list, recieved from\
			pcap_findalldevs_ex() is empty\n");
		pcap_freealldevs(_alldevs);
		return;
	}
}