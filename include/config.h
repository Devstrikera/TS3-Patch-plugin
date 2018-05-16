#pragma once

#include <string>
#include <memory>

namespace plugin {
	struct Configuration {
		struct {
			bool enabled = true;
		} blacklist;

		struct {
			bool enabled = false;
		} license;

		struct {
			bool enabled = true;
			bool notify_popup = true;
		} update;
	};

	extern std::unique_ptr<Configuration> configuration;

	namespace config {
		bool parse(std::string&);
		bool save(std::string&);
	};
}