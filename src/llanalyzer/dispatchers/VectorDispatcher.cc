#include <algorithm>

#include "VectorDispatcher.h"

namespace llanalyzer {

VectorDispatcher::~VectorDispatcher() {
    freeValues();
};

bool VectorDispatcher::Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher) {
    // If the table has size 1 and the entry is nullptr, there was nothing added yet. Just add it.
    if (table.size() == 1 && table[0] == nullptr) {
        table[0] = new Value(analyzer, dispatcher);
        lowestIdentifier = identifier;
        return true;
    }

    // If highestIdentifier == identifier, overwrite would happen -> no check needed, will return false
    if (getHighestIdentifier() < identifier) {
        table.resize(table.size() + (identifier - getHighestIdentifier()), nullptr);
    } else if (identifier < lowestIdentifier) {
        // Lower than the lowest registered identifier. Shift up by lowerBound - identifier
        identifier_t distance = lowestIdentifier - identifier;
        table.resize(table.size() + distance, nullptr);

        // Shift values
        for (ssize_t i = table.size() - 1; i >= 0; i--) {
            if (table[i] != nullptr) {
                table.at(i + distance) = table.at(i);
                table.at(i) = nullptr;
            }
        }

        lowestIdentifier = identifier;
    }

    int64_t index = identifier - lowestIdentifier;
    if (table[index] == nullptr) {
        table[index] = new Value(analyzer, dispatcher);
        return true;
    }
    return false;
}

void VectorDispatcher::Register(const register_map& data) {
    // Search smallest and largest identifier and resize vector
    const auto& lowestNew =
            std::min_element(data.begin(), data.end(),
                             [](const register_pair& a, const register_pair& b) {
                                 return a.first < b.first;
                             });

    // Register lowest first in order to do shifting only once
    Register(lowestNew->first, lowestNew->second.first, lowestNew->second.second);
    for (auto i = data.begin(); i != data.end(); i++) {
        // Already added if i == lowestNew
        if (i == lowestNew) {
            continue;
        }

        if (!Register(i->first, i->second.first, i->second.second)) {
            throw std::invalid_argument("Analyzer already registered!");
        }
    }
}

const Value* VectorDispatcher::Lookup(identifier_t identifier) const {
    int64_t index = identifier - lowestIdentifier;
    if (index >= 0 && index < table.size() && table[index] != nullptr) {
        return table[index];
    } else {
        return nullptr;
    }
}

size_t VectorDispatcher::size() const {
    size_t result = 0;
    for (const auto& current : table) {
        if (current != nullptr) {
            result++;
        }
    }
    return result;
}

void VectorDispatcher::clear() {
    freeValues();
    table.clear();
}

void VectorDispatcher::freeValues() {
    for (auto &current : table) {
        delete current;
        current = nullptr;
    }
}

void VectorDispatcher::DumpDebug() const {
#ifdef DEBUG
    DBG_LOG(DBG_LLPOC, "  Dispatcher elements (used/total): %lu/%lu", size(), table.size());
    DBG_LOG(DBG_LLPOC, "TABLE SIZE %lu", table.size());
    for (size_t i = 0; i < table.size(); i++) {
        if (table[i] != nullptr) {
            DBG_LOG(DBG_LLPOC, "    %#8lx => %s, %p", i, table[i]->analyzer->GetAnalyzerName(), table[i]->dispatcher);
        }
    }
#endif
}

}

