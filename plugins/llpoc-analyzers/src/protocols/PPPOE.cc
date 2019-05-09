#include "PPPOE.h"

using namespace plugin::Demo_Foo;

PPPOE::PPPOE() : llanalyzer::Analyzer("PPPOE"), protocol(0) {
}

PPPOE::~PPPOE() = default;

uint32_t PPPOE::getIdentifier(Packet* packet) {
    // Extract protocol identifier from PPP sublayer
    protocol = (packet->cur_pos[6] << 8u) + packet->cur_pos[7];
    return protocol;
}

void PPPOE::analyze(Packet* packet) {
    // Zeek adapter code: Set l3_proto accordingly
//    if (protocol == 0x0021) {
//        packet->l3_proto = L3_IPV4;
//    } else if (protocol == 0x0057) {
//        packet->l3_proto = L3_IPV6;
//    }

    // Set header position to next header (skip over PPPOE Session + PPP)
    packet->cur_pos = packet->cur_pos + 8;

    // "Calculate" used up data
    packet->hdr_size = 8;

    DBG_LOG(DBG_LLPOC, "Found PPPOE layer! Next is %#x", protocol);
}
