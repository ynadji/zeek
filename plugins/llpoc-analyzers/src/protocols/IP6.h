#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace plugin::Demo_Foo {

class IP6 : public llanalyzer::Analyzer {
public:
	IP6() : llanalyzer::Analyzer("IP6") {}
	~IP6() override = default;

	uint32_t getIdentifier(Packet* packet) override;
	void analyze(Packet* packet) override;

	static llanalyzer::Analyzer* Instantiate()
		{
		return new IP6();
		}

private:
	const struct ip6_hdr* ip6_header = nullptr;
	const uint8_t* savedCurPos = nullptr;
	Packet* currentPacket = nullptr;

	inline bool isExtensionHeader(uint8_t nxt_hdr)
		{
		switch (nxt_hdr)
			{
			case IPPROTO_HOPOPTS:
			case IPPROTO_DSTOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_FRAGMENT:
			case IPPROTO_AH:
				return true;
			default:
				return false;
			}
		}
};

} // end of namespace plugin::Demo_Foo
