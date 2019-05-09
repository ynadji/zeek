#pragma once

#include "Dispatcher.h"

#include <utility>

namespace llanalyzer {

class VectorDispatcher : public Dispatcher {
public:
    VectorDispatcher() : lowestIdentifier(0), table(std::vector<Value*>(1, nullptr)) {}
    ~VectorDispatcher() override;

    bool Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher) override;
    void Register(const register_map& data) override;

    const Value* Lookup(identifier_t identifier) const override;

    size_t size() const override;
    void clear() override;

protected:
    void DumpDebug() const override;

private:
    identifier_t lowestIdentifier;
    std::vector<Value*> table;

    void freeValues();

    inline identifier_t getHighestIdentifier() const {
        return lowestIdentifier + table.size() - 1;
    }
};

}