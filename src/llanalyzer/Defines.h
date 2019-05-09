#pragma once

#include <cstdint>
#include <string>
#include <map>

namespace llanalyzer {
    using identifier_t = uint32_t;
    static constexpr identifier_t NO_NEXT_LAYER = static_cast<identifier_t>(0u - 1u);
}