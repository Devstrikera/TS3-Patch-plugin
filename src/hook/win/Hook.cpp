#include <chrono>
#include <iostream>
#include <include/base64.h>
#include <thread>
#include "include/core.h"
#include "include/hook/HookWindows.h"
#include "include/hook/hook.h"
#include "include/process/module.h"
#include "include/process/pattern.h"
#include "include/wrapper/ParameterParser.h"

using namespace std;
using namespace std::chrono;
using namespace hook;
using namespace wrapper;

extern "C" {
	extern uintptr_t _hook_windows_x64_getaddrinfo_target;
	extern uintptr_t _hook_windows_x64_getaddrinfo;
	extern uintptr_t _hook_windows_x64_getaddrinfo_jump;

	extern uintptr_t _hook_windows_x64_injected_target;
	extern uintptr_t _hook_windows_x64_injected;
	extern uintptr_t _hook_windows_x64_injected_jump;

	extern uintptr_t _hook_windows_x64_getlicenseroot_target;
	extern uintptr_t _hook_windows_x64_getlicenseroot;
	extern uintptr_t _hook_windows_x64_getlicenseroot_jump;

	extern uintptr_t _hook_windows_x64_getlicenseroot1;
	extern uintptr_t _hook_windows_x64_getlicenseroot1_jump;

	extern uintptr_t _hook_windows_x64_dns_send;
	extern uintptr_t _hook_windows_x64_dns_send_target;
	extern uintptr_t _hook_windows_x64_dns_send_jump;
}

std::string HookWindows64::name() const {
	return "Windows x64";
}

bool HookWindows64::available(std::string &error) {
	if(plugin::version().find("3.1.9") != std::string::npos) {
		error = "Only available for 3.1.9";
		return false;
	}
	return true;
}

inline bool find_pattern(const std::shared_ptr<mem::MemoryRegion>& info, uintptr_t& target, const char* sig, const char* pattern, const std::string& name) {
	target = mem::find_pattern(info, string(sig, strlen(pattern)), pattern);
	cout << "Got " << name << "@" << (void*) target << endl;
	return target > 0;
}

//E8 ? ? ? ? 48 8D 4F 08 48 8B D0 E8 ? ? ? ?
#define PARAMPARSER_SIGN "\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x30\x49\x8B\xC0\xC7\x44\x24\x00\x00\x00\x00\x00\x48\x8B\xDA\x4D\x8B\xC1\x48\x8B\xD0\x48\x8B\xF9\xE8\x00\x00\x00\x00"
#define PARAMPARSER_MASK "xxxx?xxxxxxxxxxx?????xxxxxxxxxxxxx????"

bool HookWindows64::initializeHook(std::string &error) {
	//Client 1.1.9
	auto module = mem::info(MODULE_NAME);
	if(!module) {
		error = "could not find teamspeak 3 client module!";
		return false;
	}

	//auto addr_getParamValue = //1400D7060
	impl::fn_ParameterParser = new impl::ParameterParserFunctions{};
	if(!find_pattern(module, (uintptr_t&) impl::fn_ParameterParser->getParamValue, PARAMPARSER_SIGN, PARAMPARSER_MASK, "getParamValue")) {
		error = "could not find pattern for getParamValue";
		return false;
	}
	return true;
}

#define AFAIL(variable, name)\
cout << "Got address for " << name << " @ " << (void*) variable << endl; \
if(!variable) { \
	error = "could not resolve address for " name; \
	return false; \
}


#define HFAIL(variable, name) \
if(!variable) { \
	error = "could not hook " name; \
	return false; \
}

#define GETADDRINFO_SIGN "\x4C\x8D\x4C\x24\x00\x4C\x8D\x45\x8F\x33\xD2\xFF\x15\x00\x00\x00\x00\x85\xC0\x0F\x85\x00\x00\x00\x00\x48\x8B\x44\x24\x00\x8B\x48\x04\x83\xF9\x17\x75\x05\x8D\x79\xEA\xEB\x0C"
#define GETADDRINFO_MASK "xxxx?xxxxxxxx????xxxx????xxxx?xxxxxxxxxxxxx"

#define INJECTED_SIGN "\x74\x49\x48\x8D\x8C\x24\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x90\x48\x8D\x8C\x24\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x90\x48\x8D\x8C\x24\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x90\x48\x8D\x8C\x24\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x90\x48\x8D\x4C\x24\x00\xE8\x00\x00\x00\x00\x8B\xC3"
#define INJECTED_MASK "xxxxxx????x????xxxxx????x????xxxxx????x????xxxxx????x????xxxxx?x????xx"

#define STATICLICENSE_SIGN "\x4D\x2B\xC8\x48\x89\xBC\x24\x00\x00\x00\x00\x48\x8B\x15\x00\x00\x00\x00\x48\x8D\x8C\x24\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xD8\x85\xC0\x0F\x84\x00\x00\x00\x00"
#define STATICLICENSE_MASK "xxxxxxx????xxx????xxxx????x????xxxxxx????"

#define STATICLICENSE1_SIGN "\x4C\x8D\x44\x24\x00\x48\x8B\x15\x00\x00\x00\x00\x48\x8B\x9C\x24\x00\x00\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x85\xC0\x0F\x85\x00\x00\x00\x00\x48\x8B\x84\x24\x00\x00\x00\x00"
#define STATICLICENSE1_MASK "xxxx?xxx????xxxx????xxxx????xxxx????xxxx????"

bool HookWindows64::hook(std::string& error) {
	_hook_windows_x64_getaddrinfo_target = reinterpret_cast<uintptr_t>(&Hook::getaddrinfo);
	_hook_windows_x64_injected_target = reinterpret_cast<uintptr_t>(&HookWindows64::injected);
	_hook_windows_x64_getlicenseroot_target = reinterpret_cast<uintptr_t>(&Hook::getPublicKeyPtr);
	_hook_windows_x64_dns_send_target = reinterpret_cast<uintptr_t>(&HookWindows64::dns_send);
	auto module = mem::info(MODULE_NAME);
	if(!module) {
		error = "could not find Teamspeak 3 client module!";
		return false;
	}

	//This method just get called when you already have the address
	auto addr_getaddrinfo = mem::find_pattern(module, string(GETADDRINFO_SIGN, strlen(GETADDRINFO_MASK)), GETADDRINFO_MASK);
	AFAIL(addr_getaddrinfo, "getaddrinfo");
	this->hook_getaddrinfo = this->make_jmp(addr_getaddrinfo, reinterpret_cast<uintptr_t>(&_hook_windows_x64_getaddrinfo), 0x13F86F0AF - 0x13F86F09E, false);
	HFAIL(this->hook_getaddrinfo, "getaddrinfo");
	_hook_windows_x64_getaddrinfo_jump = this->hook_getaddrinfo->jumpback_address();

	auto addr_inject = mem::find_pattern(module, string(INJECTED_SIGN, strlen(INJECTED_MASK)), INJECTED_MASK);
	AFAIL(addr_inject, "injected");
	auto inject_hook = this->make_jmp(addr_inject, reinterpret_cast<uintptr_t>(&_hook_windows_x64_injected), 0x13FF6974D - 0x13FF69702, false);
	HFAIL(this->hook_getaddrinfo, "injected");
	_hook_windows_x64_injected_jump = inject_hook->jumpback_address();

	auto addr_license = mem::find_pattern(module, string(STATICLICENSE_SIGN, strlen(STATICLICENSE_MASK)), STATICLICENSE_MASK);
	AFAIL(addr_license, "static license (1)");
	this->hook_getlicenseroot_1 = this->make_jmp(addr_license, reinterpret_cast<uintptr_t>(&_hook_windows_x64_getlicenseroot), 0x1404CA0AA - 0x1404CA098, false);
	HFAIL(this->hook_getlicenseroot_1, "static license (1)");
	_hook_windows_x64_getlicenseroot_jump = this->hook_getlicenseroot_1->jumpback_address();

	auto addr_license1 = mem::find_pattern(module, string(STATICLICENSE1_SIGN, strlen(STATICLICENSE1_MASK)), STATICLICENSE1_MASK);
	AFAIL(addr_license, "static license (2)");
	auto license_hook1 = this->make_jmp(addr_license1, reinterpret_cast<uintptr_t>(&_hook_windows_x64_getlicenseroot1), 0x1404CA242 - 0x1404CA22E, false);
	HFAIL(this->hook_getaddrinfo, "static license (2)");
	_hook_windows_x64_getlicenseroot1_jump = license_hook1->jumpback_address();

	//This hook get called when TeamSpeak resolved the target (on join) domain name
	//Not required, but nice to have :D
	/*
	#define DNSSEND_SIGN "\x48\x8B\x97\x00\x00\x00\x00\x48\x8B\x4E\x20\xFF\x15\x00\x00\x00\x00\x83\xF8\xFF\x0F\x84\x00\x00\x00\x00\x8B\x87\x00\x00\x00\x00\x8B\x5D\x04\x99"
	#define DNSSEND_MASK "xxx????xxxxxx????xxxxx????xx????xxxx"

	auto addr_dns_send = mem::find_pattern(module, string(DNSSEND_SIGN, strlen(DNSSEND_MASK)), DNSSEND_MASK);
	cout << "inject addr_dns_send @" << (void*) addr_dns_send << endl;
	AFAIL(addr_dns_send, "addr_dns_send");
	auto hook_dns_send = this->make_jmp(addr_dns_send, reinterpret_cast<uintptr_t>(&_hook_windows_x64_dns_send), 0x13FB2B5AA - 0x013FB2B599, false);
	_hook_windows_x64_dns_send_jump = hook_dns_send->jumpback_address();
	*/
	return true;
}

bool HookWindows64::unhook(std::string &) {
	return false;
}

void HookWindows64::injected(void *builder) {
	cout << "Got injected builder at " << builder << endl;
	auto parser = (ParameterParser*) builder;

	ssize_t index;
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
}

int HookWindows64::dns_send(SOCKET s, const char* buf, int len, int flags) {
	return ::send(s, buf, len, flags);
}

int HookWindows64::getaddrinfo(const char* name, const char*, const addrinfo*, addrinfo**) {
	cout << "Aborting getaddrinfo(...) for address " << name << endl;
	//Notice:
	//Im just destroying this method totally, but TeamSpeak is even more incredible than this!
	//TeamSpeak just uses for all their dns resolves a own method and the real fun fun fact is,
	//that this method just get called, when they already have resolved the target address.
	//You thought that's the funniest part?! You're wrong! Totally wrong!
	//Guess what:
	//If this method fails (getaddrinfo(...) failed for an ip address WHAT?!?!), the TeamSpeak 3 client stops
	//the current request mechanism and do not event request the blacklist!
	//So as a conclusion: TeamSpeak 3 calls a unnecessary function, and stops the blacklist request if this call fails! => Fuck off TeamSpeak!

	return 1;
}