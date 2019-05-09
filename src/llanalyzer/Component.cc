// See the file "COPYING" in the main distribution directory for copyright.

#include "Component.h"
#include "Manager.h"
#include "Desc.h"

using namespace llanalyzer;

Component::Component(const std::string &name, factory_callback arg_factory, Tag::subtype_t arg_subtype, bool arg_enabled)
        : plugin::Component(plugin::component::LLANALYZER, name),
          plugin::TaggedComponent<llanalyzer::Tag>(arg_subtype) {
    factory = arg_factory;
    enabled = arg_enabled;
}

void Component::Initialize() {
    InitializeTag();
    llanalyzer_mgr->RegisterComponent(this, "LLANALYZER_");
}

Component::~Component() {
}

void Component::DoDescribe(ODesc *d) const {
    if (factory) {
        d->Add("LLANALYZER_");
        d->Add(CanonicalName());
        d->Add(", ");
    }

    d->Add(enabled ? "enabled" : "disabled");
}
