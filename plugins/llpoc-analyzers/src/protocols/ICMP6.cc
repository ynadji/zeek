#include "ICMP6.h"

using namespace plugin::Demo_Foo;

uint32_t ICMP6::getIdentifier(Packet* packet)
	{
	// No following protocol
	return -1;
	}

void ICMP6::analyze(Packet* packet)
	{
	// Do nothing for now
	DBG_LOG(DBG_LLPOC, "Found ICMP6 layer!");
	}
