#include "UniversalDispatcher.h"

namespace llanalyzer {

UniversalDispatcher::UniversalDispatcher() : a(0), b(0), wMinusM(0), generator(rd()) {
    setBins(2);

    table = std::vector<pair_t>(ONE << M, {0, nullptr});

    // Initialize random engine
    distributionA = std::uniform_int_distribution<uint64_t>(1, ~static_cast<uint64_t>(0));
    distributionB = std::uniform_int_distribution<uint64_t>(0, (ONE << wMinusM) - ONE);

    // Initialize random parameters
    randomizeAB();

    // Debug
    #if DEBUG > 0
    allCounter = 0;
    nptrCounter = 0;
    mismatchCounter = 0;
    #endif
}

UniversalDispatcher::~UniversalDispatcher() {
    freeValues();
}

bool UniversalDispatcher::Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher) {
    #if DEBUG > 1
    std::shared_ptr<void> deferred(nullptr, [=](...){ std::cout << "Inserted " << identifier << std::endl; });
    #endif

    uint64_t hashedID = hash(identifier);
    if (table[hashedID].second == nullptr) {
        // Free bin, insert the value
        table[hashedID] = std::make_pair(identifier, new Value(analyzer, dispatcher));
        return true;
    } else if (table[hashedID].first != identifier) {
        // The bin is not empty, but the content isn't the to-be-inserted identifier --> resolve collision

        // Create intermediate representation with the new element in it, then rehash with that data
        std::vector<pair_t> intermediate = createIntermediate();
        intermediate.emplace_back(identifier, new Value(analyzer, dispatcher));

        // Try increasing the #bins until it works or it can't get any larger.
        rehash(intermediate);
        return true;
    }

    // Analyzer with this ID is already registered.
    return false;
}

void UniversalDispatcher::Register(const register_map& data) {
    // Analyzer already registered
    for (const auto &current : data) {
        if (table[hash(current.first)].second != nullptr) {
            throw std::invalid_argument("Analyzer " + std::to_string(current.first) + " already registered!");
        }
    }

    // Create intermediate representation of current analyzer set, then add all new ones
    std::vector<pair_t> intermediate = createIntermediate();
    for (const auto& current : data) {
        intermediate.emplace_back(current.first, new Value(current.second.first, current.second.second));
    }

    rehash(intermediate);
}

Value* UniversalDispatcher::Lookup(identifier_t identifier) const {
    uint64_t hashedID = hash(identifier);

    // The hashedID can't be larger than the number of bins
    assert(hashedID < table.size() && "Hashed ID is outside of the hash table range!");

    pair_t entry = table[hashedID];
    if (entry.second != nullptr && entry.first == identifier) {
        return entry.second;
    }
    return nullptr;

}

size_t UniversalDispatcher::size() const {
    size_t result = 0;
    for (const auto& current : table) {
        if (current.second != nullptr) {
            result++;
        }
    }
    return result;
}

void UniversalDispatcher::clear() {
    // Free all analyzers
    freeValues();

    setBins(2);
    table = std::vector<pair_t>(ONE << M, {0, nullptr});
    randomizeAB();
}

size_t UniversalDispatcher::bucketCount() {
    return table.size();
}

void UniversalDispatcher::rehash() {
    // Intermediate representation is just the current table without nulls
    rehash(createIntermediate());
}

void UniversalDispatcher::DumpDebug() const {
#ifdef DEBUG
    DBG_LOG(DBG_LLPOC, "  Dispatcher elements (used/total): %lu/%lu", size(), table.size());
    for (size_t i = 0; i < table.size(); i++) {
        if (table[i].second != nullptr) {
            DBG_LOG(DBG_LLPOC, "    %#8x => %s, %p", table[i].first, table[i].second->analyzer->GetAnalyzerName(), table[i].second->dispatcher);
        }
    }
#endif
}

// #######################
// ####### PRIVATE #######
// #######################

void UniversalDispatcher::freeValues() {
    for (auto& current : table) {
        delete current.second;
        current.second = nullptr;
    }
}

void UniversalDispatcher::rehash(const std::vector<pair_t>& intermediate) {
    while (!findCollisionFreeHashFunction(intermediate)) {
        DBG_LOG(DBG_LLPOC, "Rehashing did not work. Increasing #bins to %lu (%lu bit).", (uint64_t) std::pow(2, M + 1), M + 1);
        setBins(M + 1);
    }
}

bool UniversalDispatcher::findCollisionFreeHashFunction(const std::vector<pair_t>& intermediate) {
    // Don't even try if the number of values is larger than the number of buckets
    if (ONE << M < intermediate.size()) {
        return false;
    }

    // Remember the hash function parameters to not break the table if rehashing doesn't work
    uint64_t stored_a = a;
    uint64_t stored_b = b;

    // Because the hash function hashes all values in the universe uniformly to m bins with probability 1/m
    // we should at least try a multiple of #bins times.
    for (size_t i = 1; i <= (ONE << M); i++) {
        // Step 1: Re-randomize hash function parameters
        randomizeAB();

        // Step 2: Create new table
        std::vector<pair_t> newTable(ONE << M, {0, nullptr});

        // Step 3: Try to insert all elements into the new table with the new hash function
        bool finished = true;
        for (const auto &current : intermediate) {
            uint64_t hashedID = hash(current.first);
            assert(hashedID < newTable.size());
            if (newTable[hashedID].second == nullptr) {
                // Free bin, insert the value
                newTable[hashedID] = current;
            } else {
                // The bin is not empty which means there is a collision
                // (there are no duplicates in the intermediate representation so that can't be the case)
                finished = false;
                break;
            }
        }

        // Step 4: If the inserting finished without collisions, overwrite the previous table and exit
        if (finished) {
            DBG_LOG(DBG_LLPOC, "Took %lu rehash(es) to resolve.", i);
            table = newTable;
            return true;
        }
    }

    // Finding a collision free hash function failed. Revert the hash function parameters.
    a = stored_a;
    b = stored_b;
    return false;
}

}