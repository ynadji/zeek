#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace plugin::Demo_Foo {

class PPPOE : public llanalyzer::Analyzer {
public:
	PPPOE() : llanalyzer::Analyzer("PPPOE") {}
	~PPPOE() override = default;

	uint32_t getIdentifier(Packet* packet) override;
	void analyze(Packet* packet) override;

	static llanalyzer::Analyzer* Instantiate()
		{
		return new PPPOE();
		}

private:
	uint16_t protocol = 0;
};

} // end of namespace plugin::Demo_Foo
