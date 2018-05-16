#pragma once

#include <string>
#include <cstddef>
#include <tuple>
#include <teamspeak/plugin_definitions.h>
#include <teamspeak/ts3_functions.h>

namespace hook {
	class Hook;
}
namespace plugin {
	extern std::string name();
	extern std::string id();
	extern void message(std::string, PluginMessageTarget);
	extern hook::Hook* hook();

	namespace api {
		extern const TS3Functions& functions();

		extern std::string version();
		extern uint64 versionNumber();
		extern std::tuple<int, int, int> version_mmp();
		inline int version_major() { return std::get<0>(version_mmp()); }
		inline int version_minor() { return std::get<1>(version_mmp()); }
		inline int version_patch() { return std::get<2>(version_mmp()); }
	}
}