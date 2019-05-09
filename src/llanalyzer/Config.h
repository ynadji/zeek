#pragma once

#include <string>
#include <map>
#include <utility>
#include <vector>
#include <algorithm>

#include "Defines.h"

namespace llanalyzer {

class DispatcherConfig {
public:
    explicit DispatcherConfig(const std::string name) : name(std::move(name)) {
    }

    const std::string& getName() const;
    const std::map<identifier_t, std::string>& getMappings() const;

    void addMapping(identifier_t identifier, const std::string& analyzerName);

    bool operator==(const DispatcherConfig &rhs) const;
    bool operator!=(const DispatcherConfig &rhs) const;

private:
    const std::string name;
    std::map<identifier_t, std::string> mappings;
};

class Config {
public:
    const std::vector<DispatcherConfig>& getDispatchers() const;
    std::optional<std::reference_wrapper<DispatcherConfig>> getDispatcherConfig(const std::string& name);
    DispatcherConfig& addDispatcherConfig(const std::string& name);
    void addMapping(const std::string& name, identifier_t identifier, const std::string& analyzerName);

private:
    std::vector<DispatcherConfig> dispatchers;
};

}