#pragma once

#include <map>
#include "Dispatcher.h"

namespace llanalyzer {

class TreeMapDispatcher : public Dispatcher {
public:
    ~TreeMapDispatcher() override;

    bool Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher) override;
    Value* Lookup(identifier_t identifier) const override;
    size_t size() const override;
    void clear() override;

    void DumpDebug() const override;

private:
    std::map<identifier_t, Value*> table;
    void freeValues();
};

}