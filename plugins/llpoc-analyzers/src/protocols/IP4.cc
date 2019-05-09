#include "IP4.h"
#include <sys/socket.h>

using namespace plugin::Demo_Foo;

IP4::IP4() : llanalyzer::Analyzer("IP4"), ip_hdr(nullptr), currentPacket(nullptr) {
}

IP4::~IP4() = default;

uint32_t IP4::getIdentifier(Packet* packet) {
    currentPacket = packet;

    ip_hdr = reinterpret_cast<const struct ip*>(packet->cur_pos);
    return ip_hdr->ip_p;
}

void IP4::analyze(Packet* packet) {
    if (currentPacket != packet) {
        getIdentifier(packet);
    }

    packet->cur_pos += ip_hdr->ip_hl;

#ifdef DEBUG
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip, INET_ADDRSTRLEN);
    DBG_LOG(DBG_LLPOC, "Found IPv4 layer: SRC_IP=%s, DST_IP=%s", src_ip, dst_ip);
#endif

    ip_hdr = nullptr;
    currentPacket = nullptr;
}
