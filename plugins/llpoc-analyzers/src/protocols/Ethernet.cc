#include "Ethernet.h"
#include "NetVar.h"

using namespace plugin::Demo_Foo;

Ethernet::Ethernet() : llanalyzer::Analyzer("Ethernet"), protocol(0), currentPacket(nullptr) {
}

Ethernet::~Ethernet() = default;

uint32_t Ethernet::getIdentifier(Packet* packet) {
    currentPacket = packet;

    // Extract protocol identifier
    protocol = (packet->cur_pos[12] << 8u) + packet->cur_pos[13];
    return protocol;
}

void Ethernet::analyze(Packet* packet) {
    if (currentPacket != packet) {
        getIdentifier(packet);
    }

    // Unfortunately some packets on the link might have MPLS labels
    // while others don't. That means we need to ask the link-layer if
    // labels are in place.
    bool have_mpls = false;

    const u_char *pdata = packet->data;
    const u_char *end_of_data = packet->data + packet->cap_len;

    // Skip past Cisco FabricPath to encapsulated ethernet frame.
    if (pdata[12] == 0x89 && pdata[13] == 0x03) {
        auto constexpr cfplen = 16;

        if (pdata + cfplen + 14 >= end_of_data) {
            packet->Weird("truncated_link_header_cfp");
            return;
        }

        pdata += cfplen;
    }

    packet->eth_type = protocol;
    packet->l2_dst = pdata;
    packet->l2_src = pdata + 6;

    pdata += 14;

    bool saw_vlan = false;

    while (protocol == 0x8100 || protocol == 0x9100 ||
           protocol == 0x8864) {
        switch (protocol) {
            // VLAN carried over the ethernet frame.
            // 802.1q / 802.1ad
            case 0x8100:
            case 0x9100: {
                if (pdata + 4 >= end_of_data) {
                    packet->Weird("truncated_link_header");
                    return;
                }

                auto &vlan_ref = saw_vlan ? packet->inner_vlan : packet->vlan;
                vlan_ref = ((pdata[0] << 8u) + pdata[1]) & 0xfff;
                protocol = ((pdata[2] << 8u) + pdata[3]);
                pdata += 4; // Skip the vlan header
                saw_vlan = true;
                packet->eth_type = protocol;
            }
                break;

            // PPPoE carried over the ethernet frame.
            case 0x8864: {
                if (pdata + 8 >= end_of_data) {
                    packet->Weird("truncated_link_header");
                    return;
                }

                protocol = (pdata[6] << 8u) + pdata[7];
                pdata += 8; // Skip the PPPoE session and PPP header

                if (protocol == 0x0021)
                    packet->l3_proto = L3_IPV4;
                else if (protocol == 0x0057)
                    packet->l3_proto = L3_IPV6;
                else {
                    // Neither IPv4 nor IPv6.
                    packet->Weird("non_ip_packet_in_pppoe_encapsulation");
                    return;
                }
            }
                break;
        }
    }

    // Check for MPLS in VLAN.
    if (protocol == 0x8847)
        have_mpls = true;

    // Normal path to determine Layer 3 protocol.
    if (!have_mpls && packet->l3_proto == L3_UNKNOWN) {
        if (protocol == 0x800)
            packet->l3_proto = L3_IPV4;
        else if (protocol == 0x86dd)
            packet->l3_proto = L3_IPV6;
        else if (protocol == 0x0806 || protocol == 0x8035)
            packet->l3_proto = L3_ARP;
        else {
            // Neither IPv4 nor IPv6.
            packet->Weird("non_ip_packet_in_ethernet");
            return;
        }
    }

    if (have_mpls) {
        // Skip the MPLS label stack.
        bool end_of_stack = false;

        while (!end_of_stack) {
            if (pdata + 4 >= end_of_data) {
                packet->Weird("truncated_link_header");
                return;
            }

            end_of_stack = *(pdata + 2u) & 0x01;
            pdata += 4;
        }

        // We assume that what remains is IP
        if (pdata + sizeof(struct ip) >= end_of_data) {
            packet->Weird("no_ip_in_mpls_payload");
            return;
        }

        const struct ip *ip = (const struct ip *) pdata;

        if (ip->ip_v == 4)
            packet->l3_proto = L3_IPV4;
        else if (ip->ip_v == 6)
            packet->l3_proto = L3_IPV6;
        else {
            // Neither IPv4 nor IPv6.
            packet->Weird("no_ip_in_mpls_payload");
            return;
        }
    } else if (encap_hdr_size) {
        // Blanket encapsulation. We assume that what remains is IP.
        if (pdata + encap_hdr_size + sizeof(struct ip) >= end_of_data) {
            packet->Weird("no_ip_left_after_encap");
            return;
        }

        pdata += encap_hdr_size;

        const struct ip *ip = (const struct ip *) pdata;

        if (ip->ip_v == 4)
            packet->l3_proto = L3_IPV4;
        else if (ip->ip_v == 6)
            packet->l3_proto = L3_IPV6;
        else {
            // Neither IPv4 nor IPv6.
            packet->Weird("no_ip_in_encap");
            return;
        }

    }

    // We've now determined (a) L3_IPV4 vs (b) L3_IPV6 vs (c) L3_ARP vs
    // (d) L3_UNKNOWN.

    // Calculate how much header we've used up.
    packet->hdr_size = (pdata - packet->data);

    protocol = 0;
    currentPacket = nullptr;
}

//void Ethernet::analyze(Packet* packet) {
//    if (currentPacket != packet) {
//        getIdentifier(packet);
//    }
//
//    packet->eth_type = protocol;
//    packet->l2_dst = packet->cur_pos;
//    packet->l2_src = packet->cur_pos + 6;
//
//    // Zeek adapter code: Set l3_proto accordingly
////    if (protocol == 0x800) {
////        packet->l3_proto = L3_IPV4;
////    } else if (protocol == 0x86dd) {
////        packet->l3_proto = L3_IPV6;
////    } else if (protocol == 0x0806 || protocol == 0x8035) {
////        packet->l3_proto = L3_ARP;
////    }
//
//    // Move position to next header
//    packet->cur_pos += 14;
//
//    // "Calculate" used up data
//    packet->hdr_size = 14;
//
//    DBG_LOG(DBG_LLPOC,
//            "Found Ethernet layer: ETH_TYPE=%#x, SRC_MAC=%02x:%02x:%02x:%02x:%02x:%02x, DST_MAC=%02x:%02x:%02x:%02x:%02x:%02x",
//            packet->eth_type,
//            packet->l2_src[0],
//            packet->l2_src[1],
//            packet->l2_src[2],
//            packet->l2_src[3],
//            packet->l2_src[4],
//            packet->l2_src[5],
//            packet->l2_dst[0],
//            packet->l2_dst[1],
//            packet->l2_dst[2],
//            packet->l2_dst[3],
//            packet->l2_dst[4],
//            packet->l2_dst[5]
//    );
//
//    protocol = 0;
//    currentPacket = nullptr;
//}
