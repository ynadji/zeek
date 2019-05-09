#include "ICMP6.h"

using namespace plugin::Demo_Foo;

ICMP6::ICMP6() : llanalyzer::Analyzer("ICMP6") {
}

ICMP6::~ICMP6() = default;

uint32_t ICMP6::getIdentifier(Packet* packet) {
    // No following protocol
    return -1;
}

void ICMP6::analyze(Packet* packet) {
    // Do nothing for now
    DBG_LOG(DBG_LLPOC, "Found ICMP6 layer!");
}
