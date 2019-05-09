#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace plugin::Demo_Foo {

class ARP : public llanalyzer::Analyzer {
public:
    ARP();
    ~ARP() override;

    uint32_t getIdentifier(Packet* packet) override;
    void analyze(Packet* packet) override;

    static llanalyzer::Analyzer* Instantiate() {
        return new ARP();
    }
};

} // end of namespace plugin::Demo_Foo
