#include "Config.h"
#include "Reporter.h"

namespace llanalyzer {
    const std::string& DispatcherConfig::getName() const {
        return name;
    }

    const std::map<identifier_t, std::string>& DispatcherConfig::getMappings() const {
        return mappings;
    }

    void DispatcherConfig::addMapping(identifier_t identifier, const std::string& analyzerName) {
        if (mappings.count(identifier)) {
            reporter->InternalError("Invalid config, identifier %x does already exist for dispatcher set %s.", identifier, name.c_str());
        }

        mappings.emplace(identifier, analyzerName);
    }

    bool DispatcherConfig::operator==(const DispatcherConfig &rhs) const {
        return name == rhs.name;
    }

    bool DispatcherConfig::operator!=(const DispatcherConfig &rhs) const {
        return !(rhs == *this);
    }

    // ##############################
    // ########### Config ###########
    // ##############################
    std::optional<std::reference_wrapper<DispatcherConfig>> Config::getDispatcherConfig(const std::string& name) {
        auto it = std::find_if(dispatchers.begin(), dispatchers.end(), [&](const DispatcherConfig& conf) {
            return conf.getName() == name;
        });

        if (it == dispatchers.end()) {
            return {};
        } else {
            return {std::ref(*it)};
        }
    }

    const std::vector<DispatcherConfig>& Config::getDispatchers() const{
        return dispatchers;
    }

    DispatcherConfig& Config::addDispatcherConfig(const std::string& name) {
        return dispatchers.emplace_back(name);
    }

    void Config::addMapping(const std::string& name, identifier_t identifier, const std::string& analyzerName) {
        // Create dispatcher config if it does not exist yet
        std::optional<std::reference_wrapper<DispatcherConfig>> dispatcherConfig = getDispatcherConfig(name);

        if (!dispatcherConfig) {
            addDispatcherConfig(name).addMapping(identifier, analyzerName);
        } else {
            dispatcherConfig->get().addMapping(identifier, analyzerName);
        }

    }
}
