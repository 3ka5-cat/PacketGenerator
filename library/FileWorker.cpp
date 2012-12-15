#include "FileWorker.h"

using namespace std;
using namespace pugi;

bool FileWorker::savePacket(const Token& name, const Tokens& formats, const Token& fileName)
{
	xml_document doc;
	xml_parse_result result = doc.load_file(fileName.c_str());
	if (result || result.status == pugi::status_file_not_found) {
		xml_node packetNode = doc.append_child("packet");
		packetNode.append_attribute("name") = name.c_str();
		for (size_t i = 0; i < formats.size(); ++i) {
			if (Utilities::startsWith(formats[i], ETH2PROTO))
				packetNode.append_attribute(ETH2PROTO.c_str()) = formats[i].c_str();			
			else if (Utilities::startsWith(formats[i], IPV4PROTO))
				packetNode.append_attribute(IPV4PROTO.c_str()) = formats[i].c_str();
			else if (Utilities::startsWith(formats[i], UDPPROTO))
				packetNode.append_attribute(UDPPROTO.c_str()) = formats[i].c_str();
			else if (Utilities::startsWith(formats[i], TCPPROTO))
				packetNode.append_attribute(TCPPROTO.c_str()) = formats[i].c_str();
			else if (Utilities::startsWith(formats[i], ICMPPROTO))
				packetNode.append_attribute(ICMPPROTO.c_str()) = formats[i].c_str();
			//else 
				//return false;
		}
		return doc.save_file(fileName.c_str());
	}
	else {
		setGlobalError(string("Packets file: error while open XML").append(result.description()));
		DbgMsg(__FILE__, __LINE__, 
			"Device::loadPacket() load_file() ERROR:\n");	
		DbgMsg(__FILE__, __LINE__, 
			"Description: %s\n", result.description());	
		DbgMsg(__FILE__, __LINE__, 
			"Error offset: %s\n", result.offset);	
		return false;		
	}				
}
bool FileWorker::loadPacket(const Token& name, Tokens& formats, const Token& fileName)
{
	xml_document doc;
	xml_parse_result result = doc.load_file(fileName.c_str());	
	if (result) {
		xml_node tmp = doc.find_child_by_attribute("name", name.c_str());		
		for (xml_attribute_iterator attribute = ++tmp.attributes_begin(); 
			attribute!=tmp.attributes_end(); ++attribute)
			formats.push_back(attribute->value());
		return true;
	}
	else if (result.status == pugi::status_file_not_found) {
		setGlobalError("Packets file: file not found");
		DbgMsg(__FILE__, __LINE__, 
			"Device::loadPacket() load_file() ERROR: file not found\n");		
		return false;
	}
	else {
		setGlobalError("Packets file: XML parsed with errors");
		DbgMsg(__FILE__, __LINE__, 
			"Device::loadPacket() load_file() ERROR: file parsed with errors:\n");	
		DbgMsg(__FILE__, __LINE__, 
			"Description: %s\n", result.description());	
		DbgMsg(__FILE__, __LINE__, 
			"Error offset: %s\n", result.offset);	
		return false;
	}	
}
bool FileWorker::loadPacket(std::vector<std::pair<Token,Tokens>>& formats, const Token& fileName)
{
	xml_document doc;
	xml_parse_result result = doc.load_file(fileName.c_str());	
	if (result) {
		Tokens packet;
		for (xml_node pkt = doc.child("packet"); pkt; pkt = pkt.next_sibling()) {
			for (xml_attribute_iterator attribute = ++pkt.attributes_begin(); 
				attribute!=pkt.attributes_end(); ++attribute)
				packet.push_back(attribute->value());						
			formats.push_back(make_pair(pkt.attributes_begin()->value(),packet));		
			packet.clear();
		}
		return true;
	}
	else if (result.status == pugi::status_file_not_found) {
		setGlobalError("Packets file: file not found");
		DbgMsg(__FILE__, __LINE__, 
			"Device::loadPacket() load_file() ERROR: file not found\n");		
		return false;
	}
	else {
		setGlobalError("Packets file: XML parsed with errors");
		DbgMsg(__FILE__, __LINE__, 
			"Device::loadPacket() load_file() ERROR: file parsed with errors:\n");	
		DbgMsg(__FILE__, __LINE__, 
			"Description: %s\n", result.description());	
		DbgMsg(__FILE__, __LINE__, 
			"Error offset: %s\n", result.offset);	
		return false;
	}	
}