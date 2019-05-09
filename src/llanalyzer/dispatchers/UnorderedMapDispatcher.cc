#include "UnorderedMapDispatcher.h"

namespace llanalyzer {

UnorderedMapDispatcher::~UnorderedMapDispatcher() {
    _clear();
}

bool UnorderedMapDispatcher::Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher) {
    auto* newValue = new Value(analyzer, dispatcher);
    if(!table.emplace(identifier, newValue).second) {
        delete newValue;
        return false;
    }

    // If there is a bucket collision, rehash
    while (containsBucketCollision()) {
        table.rehash(table.bucket_count() + 100);
    }

    return true;
}

void UnorderedMapDispatcher::Register(const register_map& data) {
    for (auto &current : data) {
        auto* newValue = new Value(current.second.first, current.second.second);
        if (!table.emplace(current.first, newValue).second) {
            delete newValue;
            throw std::invalid_argument("Analyzer already registered!");
        }
    }

    // If there is a bucket collision, rehash
    while (containsBucketCollision()) {
        table.rehash(table.bucket_count() + 100);
    }
}

const Value* UnorderedMapDispatcher::Lookup(identifier_t identifier) const {
    if (table.count(identifier) != 0) {
        return table.at(identifier);
    }

    return nullptr;
}

size_t UnorderedMapDispatcher::size() const {
    return table.size();
}

void UnorderedMapDispatcher::clear() {
    _clear();
}

void UnorderedMapDispatcher::_clear() {
    for (const auto& current : table) {
        delete current.second;
    }
    table.clear();
}

void UnorderedMapDispatcher::DumpDebug() const {
#ifdef DEBUG
    DBG_LOG(DBG_LLPOC, "  Dispatcher elements (used/total): %lu/%lu", size(), table.bucket_count());
    for (const auto& current : table) {
        DBG_LOG(DBG_LLPOC, "    %#8x => %s, %p", current.first, current.second->analyzer->GetAnalyzerName(), current.second->dispatcher);
    }
#endif
}

}
