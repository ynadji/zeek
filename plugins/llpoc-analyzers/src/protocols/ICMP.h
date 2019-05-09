#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace plugin::Demo_Foo {

class ICMP : public llanalyzer::Analyzer {
public:
    ICMP();
    ~ICMP() override;

    uint32_t getIdentifier(Packet* packet) override;
    void analyze(Packet* packet) override;

    static llanalyzer::Analyzer* Instantiate() {
        return new ICMP();
    }
};

} // end of namespace plugin::Demo_Foo
