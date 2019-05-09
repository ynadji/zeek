#pragma once

#include "Dispatcher.h"

#include <unordered_map>

namespace llanalyzer {

class UnorderedMapDispatcher : public Dispatcher {
public:
    ~UnorderedMapDispatcher() override;

    bool Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher) override;
    void Register(const register_map& data) override;
    const Value* Lookup(identifier_t identifier) const override;
    size_t size() const override;
    void clear() override;

    void DumpDebug() const override;

private:
    std::unordered_map<identifier_t, Value*> table;

    void _clear();

    inline bool containsBucketCollision() {
        for (size_t bucket = 0; bucket < table.bucket_count(); bucket++) {
            if (table.bucket_size(bucket) > 1) {
                return true;
            }
        }
        return false;
    }
};

}