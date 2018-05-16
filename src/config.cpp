#include "include/config.h"
#include "include/ini_reader.h"
#include <fstream>
#include <include/config.h>
#include <iostream>
#include <include/process/file.h>

using namespace std;
using namespace plugin;

unique_ptr<Configuration> plugin::configuration;

#define CONFIG_NAME "ts_patch.config"
#define O(stream, exp) 					\
exp; 									\
if(!stream) { 							\
	error = "unexpected io event!"; 	\
	return false; 						\
} 										\

bool config::parse(std::string& error) {
	configuration.reset(new Configuration{});
	if(!file::exists(CONFIG_NAME)) return true;

	ifstream in(CONFIG_NAME);
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
	ofstream out(CONFIG_NAME);

	auto cfg = configuration.get();
	O(out, out << 1 << " ");
	O(out, out << cfg->update.enabled << " ");
	O(out, out << cfg->update.notify_popup << " ");
	O(out, out << cfg->license.enabled << " ");
	O(out, out << cfg->blacklist.enabled << " ");
	return true;
}