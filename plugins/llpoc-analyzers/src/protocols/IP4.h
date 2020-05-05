#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace plugin::Demo_Foo {

class IP4 : public llanalyzer::Analyzer {
public:
	IP4() : llanalyzer::Analyzer("IP4") {}b
	~IP4() override = default;

	uint32_t getIdentifier(Packet* packet) override;
	void analyze(Packet* packet) override;

	static llanalyzer::Analyzer* Instantiate()
		{
		return new IP4();
		}

private:
	const struct ip* ip_hdr = nullptr;
	Packet* currentPacket = nullptr;
};

} // end of namespace plugin::Demo_Foo
