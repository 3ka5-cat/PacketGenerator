#pragma comment(lib, "packet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#define WPCAP
#define HAVE_REMOTE
#define WIN32
#include "pcap.h"


#include <iostream>
#include "debug.h"
#include "Utilities.h"

typedef const unsigned char MASK;
typedef const size_t LENGTH;
