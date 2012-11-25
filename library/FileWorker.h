#ifndef _FILEWORKER_H_
#define _FILEWORKER_H_

#pragma comment(lib, "pugixmls.lib")

#include "common.h"
#include "pugixml.hpp"

class FileWorker
{
public:	
	static bool savePacket(const Token& name, const Tokens& formats,
		const Token& fileName);
	static bool loadPacket(const Token& name, Tokens& formats, 
		const Token& fileName);
	static bool loadPacket(std::vector<std::pair<Token,Tokens>>& formats, 
		const Token& fileName);
};

#endif