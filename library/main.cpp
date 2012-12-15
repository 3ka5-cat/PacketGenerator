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
	//DbgInit("test.log");
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
	Device& selectedDevice = *(generator.device(--selected));
	Token frmt = "ETH2:000C29F2178F,16;DCA97150BDBA,16;0800,16;";
	Tokens formats;	
	formats.push_back(frmt);	
	frmt = "IPv4:4,10;5,10;65530,10;40,10;1,10;7,10;0,10;FF,16;1,10;AABB,16;3232235616,10;3232252803,10;";
	formats.push_back(frmt);	
	if (selectedDevice.buildPackets(formats))
		selectedDevice.sendPacket(formats);

	FileWorker::savePacket("qq", formats, "D:\\packets.xml");	
	formats.clear();
	frmt = "ETH2:111111111111,16;DCA97150BDBA,16;0800,16;";
	formats.push_back(frmt);
	FileWorker::savePacket("pp", formats, "D:\\packets.xml");
	vector<pair<Token,Tokens>> morePackets;	
	FileWorker::loadPacket(morePackets, "D:\\packets.xml");
	return 0;
}