#include "ARP.h"

using namespace plugin::Demo_Foo;

ARP::ARP() : llanalyzer::Analyzer("ARP") {
}

ARP::~ARP() = default;

uint32_t ARP::getIdentifier(Packet* packet) {
    // No following protocol
    return -1;
}

void ARP::analyze(Packet* packet) {
    // Do nothing for now
    DBG_LOG(DBG_LLPOC, "Found ARP layer!");
}
