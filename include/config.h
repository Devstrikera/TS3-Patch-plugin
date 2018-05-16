#pragma once

#include <string>
#include <memory>

namespace plugin {
	struct Configuration {
		struct {
			bool enabled = true;
		} blacklist;

		struct {
			bool enabled = true;
		} license;

		struct {
			bool enabled = true;
			bool notify_popup = true;
		} update;
	};

	extern std::unique_ptr<Configuration> configuration;
	extern std::string config_folder();

	namespace config {
		bool parse(std::string&);
		bool save(std::string&);
	};
}