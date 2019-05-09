// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>

#include "Analyzer.h"

namespace llanalyzer {

Analyzer::Analyzer(std::string name) {
    Tag t = llanalyzer_mgr->GetComponentTag(name);

    if (!t) {
        reporter->InternalError("unknown analyzer name %s", name.c_str());
    }

    init(t);
}

Analyzer::Analyzer(const Tag& tag) {
    init(tag);
}

/* PRIVATE */
void Analyzer::init(const Tag& _tag) {
    tag = _tag;
}

Analyzer::~Analyzer() {
}

const Tag Analyzer::GetAnalyzerTag() const {
    assert(tag);
    return tag;
}

const char* Analyzer::GetAnalyzerName() const {
	assert(tag);
	return llanalyzer_mgr->GetComponentName(tag).c_str();
}

bool Analyzer::IsAnalyzer(const char* name) {
	assert(tag);
	return strcmp(llanalyzer_mgr->GetComponentName(tag).c_str(), name) == 0;
}

} // end of llanalyzer namespace

