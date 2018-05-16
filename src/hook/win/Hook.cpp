#include <chrono>
#include <iostream>
#include <include/base64.h>
#include <thread>
#include <include/config.h>
#include "include/core.h"
#include "include/hook/HookWindows.h"
#include "include/hook/Hook.h"
#include "include/process/module.h"
#include "include/process/pattern.h"
#include "include/wrapper/ParameterParser.h"

using namespace std;
using namespace std::chrono;
using namespace hook;
using namespace wrapper;

extern "C" {
	extern uintptr_t _hook_windows_x64_getaddrinfo;
	extern uintptr_t _hook_windows_x64_getaddrinfo_target;
	extern uintptr_t _hook_windows_x64_getaddrinfo_jump;

	extern uintptr_t _hook_windows_x64_injected_316;
	extern uintptr_t _hook_windows_x64_injected_317;
	extern uintptr_t _hook_windows_x64_injected_target;
	extern uintptr_t _hook_windows_x64_injected_jump;


	extern uintptr_t _hook_windows_x64_getlicenseroot_1_316;
	extern uintptr_t _hook_windows_x64_getlicenseroot_2_316;
	extern uintptr_t _hook_windows_x64_getlicenseroot_1_317;
	extern uintptr_t _hook_windows_x64_getlicenseroot_2_317;

	extern uintptr_t _hook_windows_x64_getlicenseroot_target;
	extern uintptr_t _hook_windows_x64_getlicenseroot_1_jump;
	extern uintptr_t _hook_windows_x64_getlicenseroot_2_jump;

	extern uintptr_t _hook_windows_x64_dns_send;
	extern uintptr_t _hook_windows_x64_dns_send_target;
	extern uintptr_t _hook_windows_x64_dns_send_jump;
}

std::string HookWindows64::name() const {
	return "Windows x64";
}

bool HookWindows64::available(std::string &error) {
	auto version = plugin::api::version_mmp();
	if(get<1>(version) != 1 || get<2>(version) < 6) {
		error = "Only available for >= 3.1.6";
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


#define GETADDRINFO_SIGN "\x4C\x8D\x8E\x00\x00\x00\x00\x4C\x8D\x46\x48\x48\x8B\xD7\x48\x8B\xCB\xFF\x15\x00\x00\x00\x00\x8B\xD0\x48\x8D\x4C\x24\x00\xE8\x00\x00\x00\x00"
#define GETADDRINFO_MASK "xxx????xxxxxxxxxxxx????xxxxxx?x????"

#define INJECTED_SIGN "\x74\x49\x48\x8D\x8C\x24\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x90\x48\x8D\x8C\x24\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x90\x48\x8D\x8C\x24\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x90\x48\x8D\x8C\x24\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x90\x48\x8D\x4C\x24\x00\xE8\x00\x00\x00\x00\x8B\xC3"
#define INJECTED_MASK "xxxxxx????x????xxxxx????x????xxxxx????x????xxxxx????x????xxxxx?x????xx"

#define STATICLICENSE_1_SIGN_317 "\x4D\x2B\xC8\x48\x89\xBC\x24\x00\x00\x00\x00\x48\x8B\x15\x00\x00\x00\x00\x48\x8D\x8C\x24\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xD8\x85\xC0\x0F\x84\x00\x00\x00\x00"
#define STATICLICENSE_1_MASK_317 "xxxxxxx????xxx????xxxx????x????xxxxxx????"

#define STATICLICENSE_2_SIGN_317 "\x4C\x8D\x44\x24\x00\x48\x8B\x15\x00\x00\x00\x00\x48\x8B\x9C\x24\x00\x00\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x85\xC0\x0F\x85\x00\x00\x00\x00\x48\x8B\x84\x24\x00\x00\x00\x00"
#define STATICLICENSE_2_MASK_317 "xxxx?xxx????xxxx????xxxx????xxxx????xxxx????"

/*

Sig 4D 2B C8 48 89 BC 24 ? ? ? ? 48 8B 15 ? ? ? ? 48 8D 8C 24 ? ? ? ? E8 ? ? ? ? 90
Sig: \x4D\x2B\xC8\x48\x89\xBC\x24\x00\x00\x00\x00\x48\x8B\x15\x00\x00\x00\x00\x48\x8D\x8C\x24\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x90, xxxxxxx????xxx????xxxx????x????x
Sig 4C 8B 44 24 ? 4D 2B C8 48 89 BC 24 ? ? ? ? 48 8B 15 ? ? ? ? 48 8D 8C 24 ? ? ? ? E8 ? ? ? ? 90
Sig: \x4C\x8B\x44\x24\x00\x4D\x2B\xC8\x48\x89\xBC\x24\x00\x00\x00\x00\x48\x8B\x15\x00\x00\x00\x00\x48\x8D\x8C\x24\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x90, xxxx?xxxxxxx????xxx????xxxx????x????x
Sig 48 89 BC 24 ? ? ? ? 4C 8D 44 24 ? 48 8B 15 ? ? ? ? 48 8B 9C 24 ? ? ? ?
Sig: \x48\x89\xBC\x24\x00\x00\x00\x00\x4C\x8D\x44\x24\x00\x48\x8B\x15\x00\x00\x00\x00\x48\x8B\x9C\x24\x00\x00\x00\x00, xxxx????xxxx?xxx????xxxx????
 */
#define STATICLICENSE_1_SIGN_316 "\x4C\x8B\x44\x24\x00\x4D\x2B\xC8\x48\x89\xBC\x24\x00\x00\x00\x00\x48\x8B\x15\x00\x00\x00\x00\x48\x8D\x8C\x24\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x90"
#define STATICLICENSE_1_MASK_316 "xxxx?xxxxxxx????xxx????xxxx????x????x"

#define STATICLICENSE_2_SIGN_316 "\x48\x89\xBC\x24\x00\x00\x00\x00\x4C\x8D\x44\x24\x00\x48\x8B\x15\x00\x00\x00\x00\x48\x8B\x9C\x24\x00\x00\x00\x00"
#define STATICLICENSE_2_MASK_316 "xxxx????xxxx?xxx????xxxx????"

#define HOOK(varname, target_jump, target_bjump, publicname, sign, pattern, size) 											\
auto addr_ ##varname = mem::find_pattern(module, string(sign, strlen(pattern)), pattern); 								\
AFAIL(addr_ ##varname, publicname); 																					\
this->hook_ ##varname = this->make_jmp(addr_ ##varname, reinterpret_cast<uintptr_t>(target_jump), size, false); 		\
HFAIL(this->hook_ ##varname, publicname); 																		    	\
target_bjump = this->hook_ ##varname->jumpback_address();

bool HookWindows64::hook(std::string& error) {
	_hook_windows_x64_getaddrinfo_target = reinterpret_cast<uintptr_t>(&Hook::getaddrinfo);
	_hook_windows_x64_getlicenseroot_target = reinterpret_cast<uintptr_t>(&Hook::getPublicKeyPtr);
	_hook_windows_x64_injected_target = reinterpret_cast<uintptr_t>(&HookWindows64::injected);
	_hook_windows_x64_dns_send_target = reinterpret_cast<uintptr_t>(&HookWindows64::dns_send);
	auto module = mem::info(MODULE_NAME);
	if(!module) {
		error = "could not find Teamspeak 3 client module!";
		return false;
	}

	HOOK(getaddrinfo, &_hook_windows_x64_getaddrinfo, _hook_windows_x64_getaddrinfo_jump, "getaddrinfo", GETADDRINFO_SIGN, GETADDRINFO_MASK, 0x13FCC3DEC - 0x13FCC3DD5);

	bool version_hooked = false;
	if(plugin::api::version_minor() == 1) {
		if(plugin::api::version_patch() <= 6) {
			cout << "Using 3.1.6 data" << endl;
			HOOK(injected, &_hook_windows_x64_injected_316, _hook_windows_x64_injected_jump, "inject", INJECTED_SIGN, INJECTED_MASK, 0x13FF6974D - 0x13FF69702);
			HOOK(getlicenseroot_1, &_hook_windows_x64_getlicenseroot_1_316, _hook_windows_x64_getlicenseroot_1_jump, "static license (1)", STATICLICENSE_1_SIGN_316, STATICLICENSE_1_MASK_316, 0x1404E7E5A - 0x1404E7E43);
			HOOK(getlicenseroot_2, &_hook_windows_x64_getlicenseroot_2_316, _hook_windows_x64_getlicenseroot_2_jump, "static license (2)", STATICLICENSE_2_SIGN_316, STATICLICENSE_2_MASK_316, 0x1404E7F49 - 0x1404E7F35);

			version_hooked = true;
		} else {
			//place here the stuff bellow later
		}
	}
	//Fallback / newest
	if(!version_hooked) {
		cout << "Using >= 3.1.7 data" << endl;
		HOOK(injected, &_hook_windows_x64_injected_317, _hook_windows_x64_injected_jump, "inject", INJECTED_SIGN, INJECTED_MASK, 0x13FF6974D - 0x13FF69702);
		HOOK(getlicenseroot_1, &_hook_windows_x64_getlicenseroot_1_317, _hook_windows_x64_getlicenseroot_1_jump, "static license (1)", STATICLICENSE_1_SIGN_317, STATICLICENSE_1_MASK_317, 0x1404CA0AA - 0x1404CA098);
		HOOK(getlicenseroot_2, &_hook_windows_x64_getlicenseroot_2_317, _hook_windows_x64_getlicenseroot_2_jump, "static license (2)", STATICLICENSE_2_SIGN_317, STATICLICENSE_2_MASK_317, 0x1404CA242 - 0x1404CA22E);
	}

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
	Hook::injected((ParameterParser*) builder);
}

int HookWindows64::dns_send(SOCKET s, const char* buf, int len, int flags) {
	return ::send(s, buf, len, flags);
}