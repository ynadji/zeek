
#include "Plugin.h"

#include "protocols/Ethernet.h"
#include "protocols/PPPOE.h"
#include "protocols/ARP.h"
#include "protocols/IP4.h"
#include "protocols/IP6.h"
#include "protocols/ICMP.h"
#include "protocols/ICMP6.h"

namespace plugin::LLPOC {

Plugin plugin;

plugin::Configuration Plugin::Configure() {
    AddComponent(new ::llanalyzer::Component("Ethernet", plugin::Demo_Foo::Ethernet::Instantiate));
    AddComponent(new ::llanalyzer::Component("PPPoE", plugin::Demo_Foo::PPPOE::Instantiate));
    AddComponent(new ::llanalyzer::Component("ARP", plugin::Demo_Foo::ARP::Instantiate));
    AddComponent(new ::llanalyzer::Component("IP4", plugin::Demo_Foo::IP4::Instantiate));
    AddComponent(new ::llanalyzer::Component("IP6", plugin::Demo_Foo::IP6::Instantiate));
    AddComponent(new ::llanalyzer::Component("ICMP", plugin::Demo_Foo::ICMP::Instantiate));
    AddComponent(new ::llanalyzer::Component("ICMP6", plugin::Demo_Foo::ICMP6::Instantiate));

    plugin::Configuration config;
    config.name = "LLPOC::Analyzers";
    config.description = "A set of lower layer analyzers.";
    config.version.major = 1;
    config.version.minor = 0;
    config.version.patch = 0;
    return config;
}

}