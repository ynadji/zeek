#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace plugin::Demo_Foo {

class ICMP6 : public llanalyzer::Analyzer {
public:
    ICMP6();
    ~ICMP6() override;

    uint32_t getIdentifier(Packet* packet) override;
    void analyze(Packet* packet) override;

    static llanalyzer::Analyzer* Instantiate() {
        return new ICMP6();
    }
};

} // end of namespace plugin::Demo_Foo
