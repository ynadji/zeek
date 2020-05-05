#include "ARP.h"

using namespace plugin::Demo_Foo;

uint32_t ARP::getIdentifier(Packet* packet)
	{
	// No following protocol
	return -1;
	}

void ARP::analyze(Packet* packet)
	{
	// Do nothing for now
	DBG_LOG(DBG_LLPOC, "Found ARP layer!");
	}
