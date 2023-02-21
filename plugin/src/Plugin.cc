#include "config.h"
#include "Plugin.h"
#include <zeek/packet_analysis/Component.h>

#include "CAPWAP.h"

namespace zeek::plugin::Zeek_CAPWAP { Plugin plugin; }

using namespace zeek::plugin::Zeek_CAPWAP;

zeek::plugin::Configuration Plugin::Configure()
	{
	AddComponent(new zeek::packet_analysis::Component(
		"CAPWAP", zeek::packet_analysis::CAPWAP::CAPWAPAnalyzer::Instantiate));

	zeek::plugin::Configuration config;
	config.name = "Zeek::CAPWAP";
	config.description = "CAPWAP packet analyzer";
	config.version.major = VERSION_MAJOR;
	config.version.minor = VERSION_MINOR;
	config.version.patch = VERSION_PATCH;
	return config;
	}
