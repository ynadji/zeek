// See the file "COPYING" in the main distribution directory for copyright.

#include "Tag.h"
#include "Manager.h"

llanalyzer::Tag llanalyzer::Tag::Error;

llanalyzer::Tag::Tag(type_t type, subtype_t subtype)
        : ::Tag(llanalyzer_mgr->GetTagEnumType(), type, subtype) {
}

llanalyzer::Tag &llanalyzer::Tag::operator=(const llanalyzer::Tag &other) {
    ::Tag::operator=(other);
    return *this;
}

EnumVal* llanalyzer::Tag::AsEnumVal() const {
    return ::Tag::AsEnumVal(llanalyzer_mgr->GetTagEnumType());
}
