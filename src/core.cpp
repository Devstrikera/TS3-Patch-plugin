#include <include/hook/hook.h>
#include <iostream>
#include "../include/plugin.h"
#include <thread>
#include <deque>

using namespace std;
using namespace std::chrono;

std::string pluginId;
struct TS3Functions functions{};

namespace plugin {
	struct QueuedMessage {
		std::string message;
		PluginMessageTarget target;
	};
	deque<QueuedMessage> buffered;
	bool messagesInitialized = false;

	std::string id() {
		return pluginId;
	}

	const TS3Functions& functions() {
		return ::functions;
	}

	std::string version() {
		char* result = nullptr;
		functions().getClientLibVersion(&result);
		string res = result;
		functions().freeMemory(result);
		return res;
	}

	uint64 versionNumber() {
		uint64 number;
		functions().getClientLibVersionNumber(&number);
		return number;
	}

	void message(const std::string& message, PluginMessageTarget target, bool chat) {
		auto funcs = functions();
		if(functions().printMessage)
			functions().printMessage(funcs.getCurrentServerConnectionHandlerID(), message.c_str(), target);
		if(!messagesInitialized)
			buffered.push_back({message, target});
		if(chat)
			cout << message << endl;
	}

	void message(const std::string& message, PluginMessageTarget target) {
		plugin::message(message, target, true);
	}

	inline void guiInitialized() {
		messagesInitialized = true;
		for(const auto& e : buffered)
			message(e.message, e.target, false);
		buffered.clear();
	}
}
void ts3plugin_freeMemory(void* data) {
	if(data) free(data);
}

void ts3plugin_setFunctionPointers(const struct TS3Functions funcs) {
	functions = funcs;
}

void ts3plugin_registerPluginID(const char* id) {
	pluginId = id;
}

const char* ts3plugin_name() {
	return "License Patch";
}

const char* ts3plugin_version() {
	return "0.0.1-alpha";
}

int ts3plugin_apiVersion() {
	return 22;
}

const char* ts3plugin_author() {
	return "WolverinDEV";
}

const char* ts3plugin_description() {
	return "Allow servers to generate their own license";
}

int ts3plugin_init() {
	std::thread([](){
		this_thread::sleep_for(milliseconds(1000));
		plugin::guiInitialized();
	}).detach();
	std::string error;
	hook::Linux64Hook hook;
	auto flag = hook.available(error);
	if(!flag) {
		plugin::message("[]--------------- TS Patch ---------------[]", PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
		plugin::message("Could not inject! (No hook available)", PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
		plugin::message("[]--------------- TS Patch ---------------[]", PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
		return 1;
	}

	flag = hook.initializeHook(error);
	if(!flag) {
		plugin::message("[]--------------- TS Patch ---------------[]", PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
		plugin::message("Hook " + hook.name() + " could not be initialized", PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
		plugin::message("Reason: " + error, PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
		plugin::message("[]--------------- TS Patch ---------------[]", PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
		return 1;
	}

	flag = hook.hook(error);
	if(!flag) {
		plugin::message("[]--------------- TS Patch ---------------[]", PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
		plugin::message("Hook " + hook.name() + " could not injected", PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
		plugin::message("Reason: " + error, PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
		plugin::message("[]--------------- TS Patch ---------------[]", PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
		return 1;
	}

	plugin::message("[]--------------- TS Patch ---------------[]", PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
	plugin::message("TeamSpeak 3 patch successfully injected!", PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
	plugin::message("Features:", PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
	plugin::message("  - Blacklist bypass", PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
	plugin::message("  - Cracked 3.1 server join", PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
	plugin::message(" ", PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
	plugin::message("Plugin by WolverinDEV", PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
	plugin::message("[]--------------- TS Patch ---------------[]", PluginMessageTarget::PLUGIN_MESSAGE_TARGET_SERVER);
	return 0;
}

void ts3plugin_shutdown() { }
