#include <iostream>
#include "include/hook/hook.h"
#include <in6addr.h>
#include <cassert>

using namespace hook;
using namespace std;

std::unique_ptr<wrapper::StaticLicense> thread_local Hook::costume_license;
uintptr_t thread_local Hook::costume_license_ptr;

std::unique_ptr<mem::CodeFragment> Hook::make_jmp(uintptr_t address, uintptr_t jmp_target, size_t length, bool use_call) {
	assert(length >= 12);
	//Instructions are equal on windows & linux :D
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
			0xff, use_call ? (u_char) 0xd0 : (u_char) 0xe0,
	};
	return mem::replace(address, buffer, 12, length);
}


int Hook::getaddrinfo(const char *name, const char *service, const addrinfo *req, addrinfo **pai) {
	printf("Getting address info: %s\n", name);
	printf(" req: %p\n", req);
	printf(" pai: %p\n", pai);
	printf(" service: %p\n", (void*) service);
	printf(" name: %p\n",(void*)  name);
	auto result = ::getaddrinfo(name, service, req, pai);
	if(result > 0) return result;

	string addr(name);
	if(addr.find("blacklist") != string::npos) {
		cout << "Blacklist request! Original response: " << endl;
		for(auto entry = *pai; entry != nullptr; entry = entry->ai_next) {
			if(entry->ai_addr->sa_family == AF_INET6) {
				char astring[INET6_ADDRSTRLEN];
				auto addr = ((sockaddr_in6*) entry->ai_addr)->sin6_addr;
				inet_ntop(AF_INET6, &addr, astring, INET6_ADDRSTRLEN);
				cout << "Replacing " << astring << " to :::::" << endl;
				auto& buffer = ((sockaddr_in6*) entry->ai_addr)->sin6_addr.u;
				memset(buffer.Byte, 0, 16);
			} else if(entry->ai_addr->sa_family == AF_INET) {
				cout << "Replacing " << inet_ntoa(((sockaddr_in *) entry->ai_addr)->sin_addr) << " to 0.0.0.0" << endl;
				((sockaddr_in *) entry->ai_addr)->sin_addr.s_addr = 0;
			}
		}
	}
	cout << "Request proceeded: " << result << endl;
	return result;
}

uintptr_t Hook::getPublicKeyPtr() {
	auto result = (uintptr_t) wrapper::static_license_root;
	cout << "Got license root key request!" << endl;
	if(costume_license && costume_license_ptr > 0) {
		cout << "Using costume license key! (" << costume_license_ptr << ")" << endl;
		result = costume_license_ptr;
	} else {
		cout << "Using the standart TeamSpeak 3 key!" << endl;
	}

#ifdef WIN32
	return (uintptr_t)  result;
#else
	return (uintptr_t) &result;
#endif
}