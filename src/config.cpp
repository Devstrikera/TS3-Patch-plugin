#include "include/config.h"
#include "include/ini_reader.h"
#include <fstream>
#include <include/config.h>
#include <iostream>
#include <include/process/file.h>
#include <include/core.h>

using namespace std;
using namespace plugin;

unique_ptr<Configuration> plugin::configuration;

#define CONFIG_NAME "config.cfg"
#define O(stream, exp) 					\
exp; 									\
if(!stream) { 							\
	error = "unexpected io event!"; 	\
	return false; 						\
} 										\

std::string plugin::config_folder() {
	char buffer[512];
	plugin::api::functions().getPluginPath(buffer, 512, plugin::id().c_str());
	return string(buffer) + "ts_patch/";
}

bool config::parse(std::string& error) {
	configuration.reset(new Configuration{});
	cout << "Loading config at " << config_folder() << CONFIG_NAME << endl;
	if(!file::exists(config_folder() + CONFIG_NAME)) return true;

	ifstream in(config_folder() + CONFIG_NAME);
	auto cfg = configuration.get();

	int version;
	O(in, in >> version);
	if(version != 1) {
		error = "invalid config version (" + to_string(version) + ")";
		return false;
	}
	O(in, in >> cfg->update.enabled);
	O(in, in >> cfg->update.notify_popup);
	O(in, in >> cfg->license.enabled);
	O(in, in >> cfg->blacklist.enabled);
	return true;
}

bool config::save(std::string& error) {
	if(!file::mkdirs(config_folder())) {
		error = "could not create directories (" + config_folder() + ")";
		return false;
	}
	ofstream out(config_folder() + CONFIG_NAME);

	auto cfg = configuration.get();
	O(out, out << 1 << " ");
	O(out, out << cfg->update.enabled << " ");
	O(out, out << cfg->update.notify_popup << " ");
	O(out, out << cfg->license.enabled << " ");
	O(out, out << cfg->blacklist.enabled << " ");
	return true;
}