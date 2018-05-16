#include "include/process/memory.h"
#include "include/hook/Hook.h"
#include "include/wrapper/ParameterParser.h"
#include <include/base64.h>
#include <iostream>
#include <include/core.h>
#include <include/hook/HookLinux.h>

using namespace std;
using namespace hook;
using namespace wrapper;

std::string Linux64Hook::name() const {
	return "Linux x64";
}

bool Linux64Hook::available(std::string &string) {
	char method[8];
	mem::read(method, 0xFDD4B0, 8);
	u_char expected[8] = {0x48, 0x8D, 0x05, 0x99, 0xD6, 0x84, 0x00, 0xC3};
	return memcmp(method, expected, 8) == 0;
}

//TODO implement older clients :)
bool Linux64Hook::initializeHook(std::string &error) {
	if(plugin::api::version_patch() != 9 || plugin::api::version_minor() != 1) {
		error = "Only available for 3.1.9!";
		return false;
	}
	//Client 1.1.9
	impl::fn_ParameterParser = new impl::ParameterParserFunctions{};
    /*
    {
			(ParameterParser::fn_getLastError)      0xE98020,
			(ParameterParser::fn_getParamIndex)     0xE97520,
			(ParameterParser::fn_getParamValue)     0xE97480,
			(ParameterParser::fn_getParamValueID)   0xE97770
	};
    */
    impl::fn_ParameterParser->getLastError = (ParameterParser::fn_getLastError) 0xE98020;
    impl::fn_ParameterParser->getParamIndex = (ParameterParser::fn_getParamIndex) 0xE97520;

    impl::fn_ParameterParser->getParamValue = (ParameterParser::fn_getParamValue) 0xE97480;
    impl::fn_ParameterParser->getParamValueID = (ParameterParser::fn_getParamValueID) 0xE97770;
	return true;
}

extern uintptr_t _hook_linux_x64_getStaticLicense_target;
extern uintptr_t _hook_linux_x64_getStaticLicense;

extern uintptr_t _hook_linux_x64_injected_target;
extern uintptr_t _hook_linux_x64_injected;

extern uintptr_t _hook_linux_x64_getaddrinfo_target;
extern uintptr_t _hook_linux_x64_getaddrinfo;

bool Linux64Hook::hook(std::string& error) {
	_hook_linux_x64_getStaticLicense_target = (uintptr_t) &Linux64Hook::getPublicKeyPtr;
	this->hook_getStaticLicense = make_jmp(0xFDD4B0, (uintptr_t) &_hook_linux_x64_getStaticLicense, 12, false);

	_hook_linux_x64_injected_target = (uintptr_t) &Linux64Hook::injected;
	this->hook_cmd_clientinitivexpand2 = make_jmp(0xC827EA, (uintptr_t) &_hook_linux_x64_injected, 0xC82829 - 0xC827EA);

	_hook_linux_x64_getaddrinfo_target = (uintptr_t) &Hook::getaddrinfo;
	this->hook_getStaticLicense = make_jmp(0x466E80, (uintptr_t) &_hook_linux_x64_getaddrinfo, 12, false);

	if(!this->hook_getaddrinfo)
		cout << "hook_getaddrinfo -> failed" << endl;
	if(!this->hook_cmd_clientinitivexpand2)
		cout << "hook_cmd_clientinitivexpand2 -> failed" << endl;
	if(!this->hook_getStaticLicense)
		cout << "hook_getStaticLicense -> failed" << endl;
	return true;
}

bool Linux64Hook::unhook(std::string& error) {
	return false;
}

ssize_t Linux64Hook::injected(void* builder) {
	Hook::injected((ParameterParser*) builder);
	return ((ParameterParser*) builder)->getParamValueID("ot", index); //Just for TeamSpeak :)
}