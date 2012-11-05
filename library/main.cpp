/*
#include "common.h"
#include "TestClassCallers.h"

extern "C" UNMANAGEDDLL_API PktGen* CreatePktGen()
{
	return new PktGen();
}

extern "C" UNMANAGEDDLL_API Devices* getDevices(PktGen* pObject)
{
	if(pObject != NULL)
	{
		return &(pObject->devices());
	}
}
*/
#include <iostream>
#include <sstream>
#include "pktGen.h"


using namespace std;

// Print all the available information on the given interface
void showDevices(Devices devices)
{
	for (unsigned int i = 0; i < devices.size(); ++i) {
		cout << "[" << i+1 << "] Name: " << devices[i]->name() << endl;
		cout << "\tDescription: " << devices[i]->description() << endl;
		InterfaceAddresses addresses = devices[i]->addresses();
		for (unsigned int j = 0; j < addresses.size(); ++j) {
			cout << "\tFamily: " << addresses[j].family << endl;
			cout << "\tAddress: " << addresses[j].address << endl;
			cout << "\tNetmask: " << addresses[j].netmask << endl;
			cout << "\tLoopback: ";
			devices[j]->loopback() ? cout << "yes" : cout << "no";
			cout << endl;
			cout << "\tBroadcast Address: " << addresses[j].broadAddress << endl;
		}
		
	}
}

int main(int argc, char* argv[])
{	
	DbgInit("test.log");
	PktGen& generator = *(new PktGen());
	showDevices(generator.devices());	
	string input = "";
	unsigned int selected = 0;
	while (true) {
		cout << "Enter the interface number: ";
		getline(cin, input);		
		stringstream stream(input);				
		if (stream >> selected && selected <= generator.totalDevices() && selected > 0)
			break;
		cout << "Invalid number, please try again" << endl;
	}		
	Device& selectedDevice = generator.device(--selected);
	selectedDevice.sendPacket();

	
	return 0;
}