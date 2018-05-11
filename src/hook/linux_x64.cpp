#include <include/process/memory.h>
#include "include/hook/hook.h"
#include "include/wrapper/ParameterParser.h"

#include <include/base64.h>
#include <iostream>
#include <include/core.h>

using namespace std;
using namespace hook;
using namespace wrapper;
std::unique_ptr<wrapper::StaticLicense> thread_local Linux64Hook::costume_license;
uintptr_t thread_local Linux64Hook::costume_license_ptr;

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
	if(plugin::version().find("3.1.9")) {
		error = "Only available for 3.1.9!";
		return false;
	}
	//Client 1.1.9
	impl::fn_ParameterParser = new impl::ParameterParserFunctions {
			(ParameterParser::fn_getLastError)      0xE98020,
			(ParameterParser::fn_getParamIndex)     0xE97520,
			(ParameterParser::fn_getParamValue)     0xE97480,
			(ParameterParser::fn_getParamValueID)   0xE97770
	};
	return true;
}

extern uintptr_t _hook_linux_x64_getStaticLicense_target;
extern uintptr_t _hook_linux_x64_getStaticLicense;

extern uintptr_t _hook_linux_x64_injected_target;
extern uintptr_t _hook_linux_x64_injected;

extern uintptr_t _hook_linux_x64_getaddrinfo_target;
extern uintptr_t _hook_linux_x64_getaddrinfo;

inline std::unique_ptr<mem::CodeFragment> make_jmp(uintptr_t address, uintptr_t jmp_target, size_t length, bool call = true) {
	u_char buffer[12] = {
			0x48, 0xb8,                             //movabs %rax, $address
                     (jmp_target >>  0) & 0xFF,
                     (jmp_target >>  8) & 0xFF,
                     (jmp_target >> 16) & 0xFF,
                     (jmp_target >> 24) & 0xFF,
                     (jmp_target >> 32) & 0xFF,
                     (jmp_target >> 40) & 0xFF,
                     (jmp_target >> 48) & 0xFF,
                     (jmp_target >> 56) & 0xFF,

			//0xff, 0xe0,                           //jmp %rax
			//0xff, 0xd0,                           //call %rax
			0xff, call ? (u_char) 0xd0 : (u_char) 0xe0,
	};
	return mem::replace(address, buffer, 12, length);
}

bool Linux64Hook::hook(std::string& error) {
	_hook_linux_x64_getStaticLicense_target = (uintptr_t) &Linux64Hook::getPublicKeyPtr;
	this->hook_getStaticLicense = make_jmp(0xFDD4B0, (uintptr_t) &_hook_linux_x64_getStaticLicense, 12, false);

	_hook_linux_x64_injected_target = (uintptr_t) &Linux64Hook::injected;
	this->hook_cmd_clientinitivexpand2 = make_jmp(0xC827EA, (uintptr_t) &_hook_linux_x64_injected, 0xC82829 - 0xC827EA);

	_hook_linux_x64_getaddrinfo_target = (uintptr_t) &Linux64Hook::getaddrinfo;
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

uint64_t Linux64Hook::getPublicKeyPtr() {
	cout << "Got hooked request! Thread: " << pthread_self() << endl;
	if(costume_license && costume_license_ptr > 0) {
		cout << "Using costume license! (" << costume_license_ptr << ")" << endl;
		return (uint64_t) &costume_license_ptr;
	}
	return (uintptr_t) &wrapper::static_license_root;
}

int Linux64Hook::injected(void* builder) {
	cout << "Got injected method! Builder at: " << builder << endl;

	auto parser = (wrapper::ParameterParser*) builder;
	int index;
	cout << "Ot: " << parser->getParamValue("ot", index) << " | " << parser->getParamValueID("ot", index) << endl;
	cout << "proof: " << parser->getParamValue("proof", index) << " | " << parser->getParamValueID("ot", index) << " | " << parser->getLastError() << endl;
	cout << "has root: " << parser->hasParam("root") << " | Has dummy: " << parser->hasParam("dummy") << endl;
	cout << "root: " << parser->getParamValue("root", index) << "|" << parser->getLastError() << endl;

	if(parser->hasParam("root")) {
		auto costume_root = parser->getParamValue("root", index);
		cout << "Root key: " << costume_root << endl;
		auto root = base64::decode(costume_root);
		cout << "Length: " << root.length() << endl;

		costume_license.reset(new wrapper::StaticLicense{});
		memcpy(costume_license->publicLicense, root.data(), 32);
		costume_license_ptr = (uintptr_t) costume_license.get();
	} else {
		costume_license_ptr = 0;
		costume_license.reset();
	}

	return parser->getParamValueID("ot", index); //Just for TeamSpeak :)
}

int Linux64Hook::getaddrinfo(const char *name, const char *service, const struct addrinfo *req, struct addrinfo **pai) {
	cout << "Getting address info: " << name << endl;
	string addr(name);
	auto result = ::getaddrinfo(name, service, req, pai);
	if(result > 0) return result;

	if(addr.find("blacklist") != string::npos) {
		cout << "Blacklist request! Original response: " << endl;
		for(auto entry = *pai; entry != nullptr; entry = entry->ai_next) {
			if(entry->ai_addr->sa_family == AF_INET6) {
				char astring[INET6_ADDRSTRLEN];
				auto addr = ((sockaddr_in6*) entry->ai_addr)->sin6_addr;
				inet_ntop(AF_INET6, &addr, astring, INET6_ADDRSTRLEN);
				cout << "Replacing " << astring << " to :::::" << endl;
				auto& buffer = ((sockaddr_in6*) entry->ai_addr)->sin6_addr.__in6_u;
				memset(buffer.__u6_addr8, 0, 16);
			} else if(entry->ai_addr->sa_family == AF_INET) {
				cout << "Replacing " << inet_ntoa(((sockaddr_in *) entry->ai_addr)->sin_addr) << " to 0.0.0.0" << endl;
				((sockaddr_in *) entry->ai_addr)->sin_addr.s_addr = 0;
			}
		}
	}
	return result;
}