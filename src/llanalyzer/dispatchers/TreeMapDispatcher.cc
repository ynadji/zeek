#include "TreeMapDispatcher.h"

namespace llanalyzer {

TreeMapDispatcher::~TreeMapDispatcher() {
    freeValues();
}

bool TreeMapDispatcher::Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher) {
    return table.emplace(identifier, new Value(analyzer, dispatcher)).second;
}

Value* TreeMapDispatcher::Lookup(identifier_t identifier) const {
    if (table.count(identifier) != 0) {
        return table.at(identifier);
    } else {
        return nullptr;
    }
}

size_t TreeMapDispatcher::size() const {
    return table.size();
}

void TreeMapDispatcher::clear() {
    freeValues();
    table.clear();
}

void TreeMapDispatcher::freeValues() {
    for (auto &current : table) {
        delete current.second;
        current.second = nullptr;
    }
}

void TreeMapDispatcher::DumpDebug() const {
#ifdef DEBUG
    DBG_LOG(DBG_LLPOC, "  Dispatcher elements (used/total): %lu/%lu", size(), table.size());
    for (const auto &current : table) {
        DBG_LOG(DBG_LLPOC, "    %#8x => %s, %p", current.first, current.second->analyzer->GetAnalyzerName(), current.second->dispatcher);
    }
#endif
}

}