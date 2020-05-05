#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace plugin::Demo_Foo {

class ARP : public llanalyzer::Analyzer {
public:
	ARP() : llanalyzer::Analyzer("ARP") {}
	~ARP() override = default

	uint32_t getIdentifier(Packet* packet) override;
	void analyze(Packet* packet) override;

    static llanalyzer::Analyzer* Instantiate()
		{
		return new ARP();
		}
};

}
