#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace plugin::Demo_Foo {

class PPPOE : public llanalyzer::Analyzer {
public:
    PPPOE();
    ~PPPOE() override;

    uint32_t getIdentifier(Packet* packet) override;
    void analyze(Packet* packet) override;

    static llanalyzer::Analyzer* Instantiate() {
        return new PPPOE();
    }

private:
    uint16_t protocol;
};

} // end of namespace plugin::Demo_Foo
