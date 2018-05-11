#pragma once

#include <string>
#include <cstddef>
#include "ts3_functions.h"

namespace plugin {
	extern std::string id();
	extern const TS3Functions& functions();

	extern std::string version();
	extern uint64 versionNumber();

	extern void message(const std::string&, PluginMessageTarget);
}