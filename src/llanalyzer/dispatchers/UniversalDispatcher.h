#pragma once

#include <random>

#include "Dispatcher.h"

namespace llanalyzer {

class UniversalDispatcher : public Dispatcher {
public:
    UniversalDispatcher();
    ~UniversalDispatcher() override;

    bool Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher) override;
    void Register(const register_map& data) override;
    Value* Lookup(identifier_t identifier) const override;
    size_t size() const override;
    void clear() override;

    void DumpDebug() const override;
    size_t bucketCount();

    // Rehashes the hash table including re-randomization of the hash function.
    void rehash();

private:
    using pair_t = std::pair<identifier_t, Value*>;
    static const uint64_t ONE = 1u;

    // Chosen random constants for the currently selected collision free random hash function
    uint64_t a; // Needs to be a random odd positive value < 2^(sizeof(uint64_t) * 8)
    uint64_t b; // Needs to be a random non-negative value < 2^(((sizeof(uint64_t) * 8) - M)

    // Current bits that define the number of bins. Initially 2 which means there are 2^2 = 4 bins.
    uint64_t M = 2;

    // Current shift value which is the number of bits that are "insignificant" because of the universe size.
    uint64_t wMinusM;

    // RNG
    std::random_device rd;
    std::mt19937_64 generator;
    std::uniform_int_distribution<uint64_t> distributionA;
    std::uniform_int_distribution<uint64_t> distributionB;

    // Debug
    #if DEBUG > 0
    size_t nptrCounter;
    size_t mismatchCounter;
    size_t allCounter;
    #endif

    std::vector<pair_t> table;

    void freeValues();

    void rehash(const std::vector<pair_t>& intermediate);

    /**
     * Tries to find a collision free hash function with the current number of buckets.
     *
     * @param intermediate The key-value set to store in the hashtable.
     * @return true, iff it found a collision-free hash function.
     */
    bool findCollisionFreeHashFunction(const std::vector<pair_t>& intermediate);

    [[nodiscard]] inline uint64_t hash(const uint64_t value) const {
        return (a * value + b) >> wMinusM;
    }

    inline void randomizeAB() {
        do {
            a = distributionA(generator);
        } while (a % 2 == 0);

        b = distributionB(generator);
    }

    inline void setBins(uint64_t newM) {
        if (newM > (sizeof(uint64_t) * 8)) {
            throw std::runtime_error("Number of bits for bin count too large.");
        }

        M = newM;
        wMinusM = sizeof(uint64_t) * 8 - M;
        distributionB = std::uniform_int_distribution<uint64_t>(0, ((uint64_t)(1u) << wMinusM) - (uint64_t)(1u));
    }

    inline std::vector<pair_t> createIntermediate() {
        std::vector<pair_t> intermediate;
        for (const auto &current : table) {
            if (current.second != nullptr) {
                assert(current.second->analyzer != nullptr);
                intermediate.emplace_back(current.first, current.second);
            }
        }
        return intermediate;
    }
};

}