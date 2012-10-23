#pragma comment(lib, "packet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#define WPCAP
#define HAVE_REMOTE
#define WIN32
#include "pcap.h"

#define RET_NORMAL 0
#define RET_ERROR 1

#include <iostream>
#include "debug.h"
#include "Utilities.h"

