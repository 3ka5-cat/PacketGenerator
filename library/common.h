#ifndef _COMMON_H_

#define _COMMON_H_
#pragma comment(lib, "packet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")

#define WPCAP
#define HAVE_REMOTE
#define WIN32
#include "pcap.h"

#include "debug.h"
#include "Utilities.h"

void setGlobalError(std::string err);
const std::string& getGlobalError(void);

typedef const unsigned char MASK;
typedef const size_t LENGTH;

#endif