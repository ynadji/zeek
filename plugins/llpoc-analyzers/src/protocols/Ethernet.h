#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace plugin::Demo_Foo {

class Ethernet : public llanalyzer::Analyzer {
public:
    Ethernet();
    ~Ethernet() override;

    uint32_t getIdentifier(Packet* packet) override;
    void analyze(Packet* packet) override;

    static llanalyzer::Analyzer* Instantiate() {
        return new Ethernet();
    }

private:
    uint16_t protocol;
    Packet* currentPacket;
};

} // end of namespace plugin::Demo_Foo
